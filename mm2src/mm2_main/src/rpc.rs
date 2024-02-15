/******************************************************************************
 * Copyright © 2023 Pampex LTD and TillyHK LTD              *
 *                                                                            *
 * See the CONTRIBUTOR-LICENSE-AGREEMENT, COPYING, LICENSE-COPYRIGHT-NOTICE   *
 * and DEVELOPER-CERTIFICATE-OF-ORIGIN files in the LEGAL directory in        *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * Komodo DeFi Framework software, including this file may be copied, modified, propagated*
 * or distributed except according to the terms contained in the              *
 * LICENSE-COPYRIGHT-NOTICE file.                                             *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  rpc.rs
//
//  Copyright © 2023 Pampex LTD and TillyHK LTD. All rights reserved.
//

use crate::mm2::rpc::rate_limiter::RateLimitError;
use common::log::{error, info};
use common::{err_to_rpc_json_string, err_tp_rpc_json, HttpStatusCode, APPLICATION_JSON};
use derive_more::Display;
use futures::future::{join_all, FutureExt};
use http::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use http::request::Parts;
use http::{Method, Request, Response, StatusCode};
use lazy_static::lazy_static;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use mm2_rpc::mm_protocol::{MmRpcBuilder, MmRpcResponse, MmRpcVersion};
use regex::Regex;
use serde::Serialize;
use serde_json::{self as json, Value as Json};
use std::borrow::Cow;
use std::net::SocketAddr;

cfg_native! {
    use hyper::{self, Body, Server};
    use mm2_net::sse_handler::{handle_sse, SSE_ENDPOINT};
}

#[path = "rpc/dispatcher/dispatcher.rs"] mod dispatcher;
#[path = "rpc/dispatcher/dispatcher_legacy.rs"]
mod dispatcher_legacy;
#[path = "rpc/lp_commands/lp_commands.rs"] pub mod lp_commands;
#[path = "rpc/lp_commands/lp_commands_legacy.rs"]
pub mod lp_commands_legacy;
#[path = "rpc/rate_limiter.rs"] mod rate_limiter;

/// Lists the RPC method not requiring the "userpass" authentication.  
/// None is also public to skip auth and display proper error in case of method is missing
const PUBLIC_METHODS: &[Option<&str>] = &[
    // Sorted alphanumerically (on the first letter) for readability.
    Some("fundvalue"),
    Some("getprice"),
    Some("getpeers"),
    Some("getcoins"),
    Some("help"),
    Some("metrics"),
    Some("notify"), // Manually checks the peer's public key.
    Some("orderbook"),
    Some("passphrase"), // Manually checks the "passphrase".
    Some("pricearray"),
    Some("psock"),
    Some("statsdisp"),
    Some("stats_swap_status"),
    Some("tradesarray"),
    Some("ticker"),
    Some("version"),
    None,
];

pub type DispatcherResult<T> = Result<T, MmError<DispatcherError>>;

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum DispatcherError {
    #[display(fmt = "Your ip is banned.")]
    Banned,
    #[display(fmt = "No such method")]
    NoSuchMethod,
    #[display(fmt = "Error parsing request: {}", _0)]
    InvalidRequest(String),
    #[display(fmt = "Selected method can be called from localhost only!")]
    LocalHostOnly,
    #[display(fmt = "Userpass is not set!")]
    UserpassIsNotSet,
    #[display(fmt = "Userpass is invalid! - {}", _0)]
    UserpassIsInvalid(RateLimitError),
    #[display(fmt = "Error parsing mmrpc version: {}", _0)]
    InvalidMmRpcVersion(String),
}

impl HttpStatusCode for DispatcherError {
    fn status_code(&self) -> StatusCode {
        match self {
            DispatcherError::NoSuchMethod
            | DispatcherError::InvalidRequest(_)
            | DispatcherError::InvalidMmRpcVersion(_) => StatusCode::BAD_REQUEST,
            DispatcherError::LocalHostOnly
            | DispatcherError::UserpassIsNotSet
            | DispatcherError::UserpassIsInvalid(_)
            | DispatcherError::Banned => StatusCode::FORBIDDEN,
        }
    }
}

impl From<serde_json::Error> for DispatcherError {
    fn from(e: serde_json::Error) -> Self { DispatcherError::InvalidRequest(e.to_string()) }
}

#[allow(unused_macros)]
macro_rules! unwrap_or_err_response {
    ($e:expr, $($args:tt)*) => {
        match $e {
            Ok(ok) => ok,
            Err(err) => return rpc_err_response(500, &ERRL!("{}", err)),
        }
    };
}

async fn process_json_batch_requests(ctx: MmArc, requests: &[Json], client: SocketAddr) -> Result<Json, String> {
    let mut futures = Vec::with_capacity(requests.len());
    for request in requests {
        futures.push(process_single_request(ctx.clone(), request.clone(), client));
    }
    let results = join_all(futures).await;
    let responses: Vec<_> = results
        .into_iter()
        .map(|resp| match resp {
            Ok(r) => match json::from_slice(r.body()) {
                Ok(j) => j,
                Err(e) => {
                    error!("Response {:?} is not a valid JSON, error: {}", r, e);
                    Json::Null
                },
            },
            Err(e) => err_tp_rpc_json(e),
        })
        .collect();
    Ok(Json::Array(responses))
}

#[cfg(target_arch = "wasm32")]
async fn process_json_request(ctx: MmArc, req_json: Json, client: SocketAddr) -> Result<Json, String> {
    if let Some(requests) = req_json.as_array() {
        return process_json_batch_requests(ctx, requests, client)
            .await
            .map_err(|e| ERRL!("{}", e));
    }

    let r = try_s!(process_single_request(ctx, req_json, client).await);
    json::from_slice(r.body()).map_err(|e| ERRL!("Response {:?} is not a valid JSON, error: {}", r, e))
}

#[cfg(not(target_arch = "wasm32"))]
async fn process_json_request(ctx: MmArc, req_json: Json, client: SocketAddr) -> Result<Response<Vec<u8>>, String> {
    if let Some(requests) = req_json.as_array() {
        let response = try_s!(process_json_batch_requests(ctx, requests, client).await);
        let res = try_s!(json::to_vec(&response));
        return Ok(try_s!(Response::builder().body(res)));
    }

    process_single_request(ctx, req_json, client).await
}

fn response_from_dispatcher_error(
    error: MmError<DispatcherError>,
    version: MmRpcVersion,
    id: Option<usize>,
) -> Response<Vec<u8>> {
    error!("RPC dispatcher error: {}", error);
    let response: MmRpcResponse<(), _> = MmRpcBuilder::err(error).version(version).id(id).build();
    response.serialize_http_response()
}

pub fn escape_answer<'a, S: Into<Cow<'a, str>>>(input: S) -> Cow<'a, str> {
    lazy_static! {
        static ref REGEX: Regex = Regex::new("[<>&]").unwrap();
    }

    let input = input.into();
    let mut last_match = 0;

    if REGEX.is_match(&input) {
        let matches = REGEX.find_iter(&input);
        let mut output = String::with_capacity(input.len());
        for mat in matches {
            let (begin, end) = (mat.start(), mat.end());
            output.push_str(&input[last_match..begin]);
            match &input[begin..end] {
                "<" => output.push_str("&lt;"),
                ">" => output.push_str("&gt;"),
                "&" => output.push_str("&amp;"),
                _ => unreachable!(),
            }
            last_match = end;
        }
        output.push_str(&input[last_match..]);
        Cow::Owned(output)
    } else {
        input
    }
}

async fn process_single_request(ctx: MmArc, req: Json, client: SocketAddr) -> Result<Response<Vec<u8>>, String> {
    let local_only = ctx.conf["rpc_local_only"].as_bool().unwrap_or(true);
    if req["mmrpc"].is_null() {
        return dispatcher_legacy::process_single_request(ctx, req, client, local_only)
            .await
            .map_err(|e| ERRL!("{}", e));
    }

    let id = req["id"].as_u64().map(|id| id as usize);
    let version: MmRpcVersion = match json::from_value(req["mmrpc"].clone()) {
        Ok(v) => v,
        Err(e) => {
            let error = MmError::new(DispatcherError::InvalidMmRpcVersion(e.to_string()));
            // use the latest `MmRpcVersion` if the version is not recognized
            return Ok(response_from_dispatcher_error(error, MmRpcVersion::V2, id));
        },
    };

    match dispatcher::process_single_request(ctx, req, client, local_only).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // return always serialized response
            Ok(response_from_dispatcher_error(e, version, id))
        },
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn rpc_service(req: Request<Body>, ctx_h: u32, client: SocketAddr) -> Response<Body> {
    /// Unwraps a result or propagates its error 500 response with the specified headers (if they are present).
    macro_rules! try_sf {
        ($value: expr $(, $header_key:expr => $header_val:expr)*) => {
            match $value {
                Ok(ok) => ok,
                Err(err) => {
                    error!("RPC error response: {}", err);
                    let ebody = err_to_rpc_json_string(&err.to_string());
                    // generate a `Response` with the headers specified in `$header_key` and `$header_val`
                    let response = Response::builder().status(500) $(.header($header_key, $header_val))* .body(Body::from(ebody)).unwrap();
                    return response;
                },
            }
        };
    }

    async fn process_rpc_request(
        ctx: MmArc,
        req: Parts,
        req_json: Json,
        client: SocketAddr,
    ) -> Result<Response<Vec<u8>>, String> {
        if req.method != Method::POST {
            return ERR!("Only POST requests are supported!");
        }

        process_json_request(ctx, req_json, client).await
    }

    let ctx = try_sf!(MmArc::from_ffi_handle(ctx_h));
    // https://github.com/artemii235/SuperNET/issues/219
    let rpc_cors = match ctx.conf["rpccors"].as_str() {
        Some(s) => try_sf!(HeaderValue::from_str(s)),
        None => HeaderValue::from_static("http://localhost:3000"),
    };

    // Convert the native Hyper stream into a portable stream of `Bytes`.
    let (req, req_body) = req.into_parts();
    let req_bytes = try_sf!(hyper::body::to_bytes(req_body).await, ACCESS_CONTROL_ALLOW_ORIGIN => rpc_cors);
    let req_str = String::from_utf8_lossy(req_bytes.as_ref());
    let is_invalid_input = req_str.chars().any(|c| c == '<' || c == '>' || c == '&');
    if is_invalid_input {
        return Response::builder()
            .status(500)
            .header(CONTENT_TYPE, APPLICATION_JSON)
            .body(Body::from(err_to_rpc_json_string("Invalid input")))
            .unwrap();
    }
    let req_json: Json = try_sf!(json::from_slice(&req_bytes), ACCESS_CONTROL_ALLOW_ORIGIN => rpc_cors);

    let res = try_sf!(process_rpc_request(ctx, req, req_json, client).await, ACCESS_CONTROL_ALLOW_ORIGIN => rpc_cors);
    let (mut parts, body) = res.into_parts();
    parts.headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, rpc_cors);
    let body_escaped = match std::str::from_utf8(&body) {
        Ok(body_utf8) => {
            let escaped = escape_answer(body_utf8);
            escaped.as_bytes().to_vec()
        },
        Err(_) => {
            return Response::builder()
                .status(500)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Body::from(err_to_rpc_json_string("Non UTF-8 output")))
                .unwrap();
        },
    };
    Response::from_parts(parts, Body::from(body_escaped))
}

// TODO: This should exclude TCP internals, as including them results in having to
// handle various protocols within this function.
#[cfg(not(target_arch = "wasm32"))]
pub extern "C" fn spawn_rpc(ctx_h: u32) {
    use common::now_sec;
    use common::wio::CORE;
    use hyper::server::conn::{AddrIncoming, AddrStream};
    use hyper::service::{make_service_fn, service_fn};
    use mm2_net::native_tls::{TlsAcceptor, TlsStream};
    use rcgen::{generate_simple_self_signed, RcgenError};
    use rustls::{Certificate, PrivateKey};
    use rustls_pemfile as pemfile;
    use std::convert::Infallible;
    use std::env;
    use std::fs::File;
    use std::io::{self, BufReader};

    // Reads a certificate and a key from the specified files.
    fn read_certificate_and_key(
        cert_file: &File,
        cert_key_path: &str,
    ) -> Result<(Vec<Certificate>, PrivateKey), io::Error> {
        let cert_file = &mut BufReader::new(cert_file);
        let cert_chain = pemfile::certs(cert_file)?.into_iter().map(Certificate).collect();
        let key_file = &mut BufReader::new(File::open(cert_key_path)?);
        let key = pemfile::read_all(key_file)?
            .into_iter()
            .find_map(|item| match item {
                pemfile::Item::RSAKey(key) | pemfile::Item::PKCS8Key(key) | pemfile::Item::ECKey(key) => Some(key),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No private key found"))?;
        Ok((cert_chain, PrivateKey(key)))
    }

    // Generates a self-signed certificate
    fn generate_self_signed_cert(subject_alt_names: Vec<String>) -> Result<(Vec<Certificate>, PrivateKey), RcgenError> {
        // Generate the certificate
        let cert = generate_simple_self_signed(subject_alt_names)?;
        let cert_der = cert.serialize_der()?;
        let privkey = PrivateKey(cert.serialize_private_key_der());
        let cert = Certificate(cert_der);
        let cert_chain = vec![cert];
        Ok((cert_chain, privkey))
    }

    // NB: We need to manually handle the incoming connections in order to get the remote IP address,
    // cf. https://github.com/hyperium/hyper/issues/1410#issuecomment-419510220.
    // Although if the ability to access the remote IP address is solved by the Hyper in the future
    // then we might want to refactor into starting it ideomatically in order to benefit from a more graceful shutdown,
    // cf. https://github.com/hyperium/hyper/pull/1640.

    let ctx = MmArc::from_ffi_handle(ctx_h).expect("No context");

    let is_event_stream_enabled = ctx.event_stream_configuration.is_some();

    let make_svc_fut = move |remote_addr: SocketAddr| async move {
        Ok::<_, Infallible>(service_fn(move |req: Request<Body>| async move {
            if is_event_stream_enabled && req.uri().path() == SSE_ENDPOINT {
                let res = handle_sse(req, ctx_h).await?;
                return Ok::<_, Infallible>(res);
            }

            let res = rpc_service(req, ctx_h, remote_addr).await;
            Ok::<_, Infallible>(res)
        }))
    };

    //The `make_svc` macro creates a `make_service_fn` for a specified socket type.
    // `$socket_type`: The socket type with a `remote_addr` method that returns a `SocketAddr`.
    macro_rules! make_svc {
        ($socket_type:ty) => {
            make_service_fn(move |socket: &$socket_type| {
                let remote_addr = socket.remote_addr();
                make_svc_fut(remote_addr)
            })
        };
    }

    // The `get_shutdown_future` macro registers a graceful shutdown listener by calling the `register_listener`
    // method of `GracefulShutdownRegistry`.
    // If the `register_listener` method fails, it implies that the application is already in a shutdown state.
    // In this case, the macro logs an error and immediately returns.
    macro_rules! get_shutdown_future {
        ($ctx:expr) => {
            match $ctx.graceful_shutdown_registry.register_listener() {
                Ok(shutdown_fut) => shutdown_fut,
                Err(e) => {
                    error!("MmCtx seems to be stopped already: {e}");
                    return;
                },
            }
        };
    }

    // Macro for spawning a server with error handling and logging
    macro_rules! spawn_server {
        ($server:expr, $ctx:expr, $ip:expr, $port:expr) => {
            {
                let server = $server.then(|r| {
                    if let Err(err) = r {
                        error!("{}", err);
                    };
                    futures::future::ready(())
                });

                // As it's said in the [issue](https://github.com/hyperium/tonic/issues/330):
                //
                // Aborting the server future will forcefully cancel all connections and not perform a proper drain/shutdown.
                // While using the special shutdown methods on the server will allow hyper to gracefully drain all connections
                // and gracefully close connections.
                common::executor::spawn({
                    log_tag!(
                        $ctx,
                        "😉";
                        fmt = ">>>>>>>>>> DEX stats {}:{} DEX stats API enabled at unixtime.{} <<<<<<<<<",
                        $ip,
                        $port,
                        now_sec()
                    );
                    let _ = $ctx.rpc_started.pin(true);
                    server
                });
            }
        };
    }

    let rpc_ip_port = ctx
        .rpc_ip_port()
        .unwrap_or_else(|err| panic!("Invalid RPC port: {}", err));
    // By entering the context, we tie `tokio::spawn` to this executor.
    let _runtime_guard = CORE.0.enter();

    if ctx.is_https() {
        let cert_path = env::var("MM_CERT_PATH").unwrap_or_else(|_| "cert.pem".to_string());
        let (cert_chain, privkey) = match File::open(cert_path.clone()) {
            Ok(cert_file) => {
                let cert_key_path = env::var("MM_CERT_KEY_PATH").unwrap_or_else(|_| "key.pem".to_string());
                read_certificate_and_key(&cert_file, &cert_key_path)
                    .unwrap_or_else(|err| panic!("Can't read certificate and/or key from {:?}: {}", cert_path, err))
            },
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                info!(
                    "No certificate found at {:?}, generating a self-signed certificate",
                    cert_path
                );
                let subject_alt_names = ctx
                    .alt_names()
                    .unwrap_or_else(|err| panic!("Invalid `alt_names` config: {}", err));
                generate_self_signed_cert(subject_alt_names)
                    .unwrap_or_else(|err| panic!("Can't generate self-signed certificate: {}", err))
            },
            Err(err) => panic!("Can't open {:?}: {}", cert_path, err),
        };

        // Create a TcpListener
        let incoming =
            AddrIncoming::bind(&rpc_ip_port).unwrap_or_else(|err| panic!("Can't bind on {}: {}", rpc_ip_port, err));
        let acceptor = TlsAcceptor::builder()
            .with_single_cert(cert_chain, privkey)
            .unwrap_or_else(|err| panic!("Can't set certificate for TlsAcceptor: {}", err))
            .with_all_versions_alpn()
            .with_incoming(incoming);

        let server = Server::builder(acceptor)
            .http1_half_close(false)
            .serve(make_svc!(TlsStream))
            .with_graceful_shutdown(get_shutdown_future!(ctx));

        spawn_server!(server, ctx, rpc_ip_port.ip(), rpc_ip_port.port());
    } else {
        let server = Server::try_bind(&rpc_ip_port)
            .unwrap_or_else(|err| panic!("Can't bind on {}: {}", rpc_ip_port, err))
            .http1_half_close(false)
            .serve(make_svc!(AddrStream))
            .with_graceful_shutdown(get_shutdown_future!(ctx));

        spawn_server!(server, ctx, rpc_ip_port.ip(), rpc_ip_port.port());
    }
}

#[cfg(target_arch = "wasm32")]
pub fn spawn_rpc(ctx_h: u32) {
    use common::executor::SpawnFuture;
    use futures::StreamExt;
    use mm2_rpc::wasm_rpc;
    use std::sync::Mutex;

    let ctx = MmArc::from_ffi_handle(ctx_h).expect("No context");
    if ctx.wasm_rpc.is_some() {
        error!("RPC is initialized already");
        return;
    }

    let client: SocketAddr = "127.0.0.1:1"
        .parse()
        .expect("'127.0.0.1:1' must be valid socket address");

    let (request_tx, mut request_rx) = wasm_rpc::channel();
    let ctx_weak = ctx.weak();
    let fut = async move {
        while let Some((request_json, response_tx)) = request_rx.next().await {
            let ctx = match MmArc::from_weak(&ctx_weak) {
                Some(ctx) => ctx,
                None => break,
            };

            let spawner = ctx.spawner();
            let request_fut = async move {
                let response = process_json_request(ctx, request_json, client).await;
                if let Err(e) = response_tx.send(response) {
                    error!("Response is not processed: {:?}", e);
                }
            };
            // Spawn the `request_fut` so the requests can be processed asynchronously.
            // Fixes: https://github.com/KomodoPlatform/atomicDEX-API/issues/1616
            spawner.spawn(request_fut);
        }
    };
    ctx.spawner().spawn(fut);

    // even if the [`MmCtx::wasm_rpc`] is initialized already, the spawned future above will be shutdown
    if let Err(e) = ctx.wasm_rpc.pin(request_tx) {
        error!("'MmCtx::wasm_rpc' is initialized already: {}", e);
        return;
    };
    if let Err(e) = ctx.rpc_started.pin(true) {
        error!("'MmCtx::rpc_started' is set already: {}", e);
        return;
    }

    log_tag!(
        ctx,
        "😉";
        fmt = ">>>>>>>>>> DEX stats API enabled at unixtime.{}  <<<<<<<<<",
        common::now_ms() / 1000
    );
}
