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
use serde::{Serialize, Serializer};
use serde::de::{Deserializer, DeserializeOwned, Visitor};
use serde_json::{self as json, Value as Json};
use std::convert::TryFrom;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use crate::tezos::TezosRpcValue;
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
                log!([b]);
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

fn big_uint_to_string<S>(num: &BigUint, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
    s.serialize_str(&num.to_string())
}

fn big_uint_from_str<'de, D>(d: D) -> Result<BigUint, D::Error> where D: Deserializer<'de> {
    struct BigUintStringVisitor;

    impl<'de> Visitor<'de> for BigUintStringVisitor {
        type Value = BigUint;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string containing json data")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
        {
            BigUint::from_str(v).map_err(E::custom)
        }
    }

    d.deserialize_any(BigUintStringVisitor)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Operation {
    #[serde(deserialize_with = "big_uint_from_str")]
    #[serde(serialize_with = "big_uint_to_string")]
    pub amount: BigUint,
    #[serde(deserialize_with = "big_uint_from_str")]
    #[serde(serialize_with = "big_uint_to_string")]
    pub counter: BigUint,
    pub destination: String,
    #[serde(deserialize_with = "big_uint_from_str")]
    #[serde(serialize_with = "big_uint_to_string")]
    pub fee: BigUint,
    #[serde(deserialize_with = "big_uint_from_str")]
    #[serde(serialize_with = "big_uint_to_string")]
    pub gas_limit: BigUint,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<TezosRpcValue>,
    pub source: String,
    #[serde(deserialize_with = "big_uint_from_str")]
    #[serde(serialize_with = "big_uint_to_string")]
    pub storage_limit: BigUint,
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

    pub async fn operation_hashes(&self, block_id: &str) -> Result<Vec<String>, String> {
        let mut path = format!("/chains/main/blocks/{}/operation_hashes", block_id);
        let hashes: Vec<Vec<String>> = try_s!(tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e)));
        Ok(hashes.into_iter().flatten().collect())
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

    let bytes = [28, 203, 245, 206, 14, 136, 243, 42, 74, 60, 66, 250, 245, 205, 120, 89, 241, 51, 209, 159, 122, 250, 220, 196, 210, 201, 106, 35, 109, 127, 132, 89, 8, 0, 0, 41, 105, 115, 114, 48, 189, 94, 166, 15, 99, 43, 82, 119, 121, 129, 228, 58, 37, 208, 105, 160, 141, 6, 219, 4, 128, 234, 48, 224, 212, 3, 192, 132, 61, 1, 25, 33, 9, 71, 111, 25, 74, 96, 57, 130, 193, 207, 192, 40, 181, 250, 214, 91, 120, 145, 0, 255, 0, 0, 0, 118, 0, 5, 5, 7, 7, 10, 0, 0, 0, 1, 37, 7, 7, 1, 0, 0, 0, 20, 49, 57, 55, 48, 45, 48, 49, 45, 48, 49, 84, 48, 48, 58, 48, 48, 58, 48, 48, 90, 7, 7, 10, 0, 0, 0, 32, 102, 104, 122, 173, 248, 98, 189, 119, 108, 143, 193, 139, 142, 159, 142, 32, 8, 151, 20, 133, 110, 226, 51, 179, 144, 42, 89, 29, 13, 95, 41, 37, 1, 0, 0, 0, 36, 100, 110, 49, 75, 117, 116, 102, 104, 52, 101, 119, 116, 78, 120, 117, 57, 70, 99, 119, 68, 72, 102, 122, 55, 88, 52, 83, 87, 117, 87, 90, 100, 82, 71, 121, 112];
    log!((bytes.len()));
}
