#[cfg(all(feature = "zhtlc-native-tests", not(target_arch = "wasm32")))]
use super::enable_z_coin;
use crate::integration_tests_common::*;
use common::executor::Timer;
use common::{cfg_native, cfg_wasm32, get_utc_timestamp, log, new_uuid};
use crypto::privkey::key_pair_from_seed;
use crypto::StandardHDCoinAddress;
use http::{HeaderMap, StatusCode};
use mm2_main::mm2::lp_ordermatch::MIN_ORDER_KEEP_ALIVE_INTERVAL;
use mm2_metrics::{MetricType, MetricsJson};
use mm2_number::{BigDecimal, BigRational, Fraction, MmNumber};
use mm2_rpc::data::legacy::{CoinInitResponse, MmVersionResponse, OrderbookResponse};
use mm2_test_helpers::electrums::*;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "zhtlc-native-tests")))]
use mm2_test_helpers::for_tests::check_stats_swap_status;
#[cfg(all(not(target_arch = "wasm32")))]
use mm2_test_helpers::for_tests::{btc_segwit_conf, btc_with_spv_conf, btc_with_sync_starting_header,
                                  check_recent_swaps, enable_eth_coin, enable_qrc20, eth_jst_testnet_conf,
                                  eth_testnet_conf, find_metrics_in_json, from_env_file, get_shared_db_id, mm_spat,
                                  morty_conf, rick_conf, sign_message, start_swaps, tbtc_segwit_conf,
                                  tbtc_with_spv_conf, test_qrc20_history_impl, tqrc20_conf, verify_message,
                                  wait_for_swap_contract_negotiation, wait_for_swap_negotiation_failure,
                                  wait_for_swaps_finish_and_check_status, wait_till_history_has_records,
                                  MarketMakerIt, Mm2InitPrivKeyPolicy, Mm2TestConf, Mm2TestConfForSwap, RaiiDump,
                                  DOC_ELECTRUM_ADDRS, ETH_DEV_NODES, ETH_DEV_SWAP_CONTRACT, ETH_DEV_TOKEN_CONTRACT,
                                  ETH_MAINNET_NODE, ETH_MAINNET_SWAP_CONTRACT, MARTY_ELECTRUM_ADDRS, MORTY,
                                  QRC20_ELECTRUMS, RICK, RICK_ELECTRUM_ADDRS, TBTC_ELECTRUMS, T_BCH_ELECTRUMS};
use mm2_test_helpers::get_passphrase;
use mm2_test_helpers::structs::*;
use serde_json::{self as json, json, Value as Json};
use std::collections::HashMap;
use std::env::{self, var};
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use uuid::Uuid;

cfg_native! {
    use common::block_on;
    use mm2_test_helpers::for_tests::{get_passphrase, new_mm2_temp_folder_path};
    use mm2_io::fs::slurp;
    use hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN;
}

cfg_wasm32! {
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);
}

/// Integration test for RPC server.
/// Check that MM doesn't crash in case of invalid RPC requests
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_rpc() {
    let (_, mm, _dump_log, _dump_dashboard) = mm_spat();

    let no_method = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "coin": "RICK",
        "ipaddr": "electrum1.cipig.net",
        "port": 10017
    })))
    .unwrap();
    assert!(no_method.0.is_server_error());
    assert_eq!((no_method.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let not_json = mm.rpc_str("It's just a string").unwrap();
    assert!(not_json.0.is_server_error());
    assert_eq!((not_json.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let unknown_method = block_on(mm.rpc(&json! ({
        "method": "unknown_method",
    })))
    .unwrap();

    assert!(unknown_method.0.is_server_error());
    assert_eq!((unknown_method.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    let version = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "version",
    })))
    .unwrap();
    assert_eq!(version.0, StatusCode::OK);
    assert_eq!((version.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");
    let _version: MmVersionResponse = json::from_str(&version.1).unwrap();

    let help = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "help",
    })))
    .unwrap();
    assert_eq!(help.0, StatusCode::OK);
    assert_eq!((help.2)[ACCESS_CONTROL_ALLOW_ORIGIN], "http://localhost:4000");

    block_on(mm.stop()).unwrap();
    // unwrap! (mm.wait_for_log (9., &|log| log.contains ("on_stop] firing shutdown_tx!")));
    // TODO (workaround libtorrent hanging in delete) // unwrap! (mm.wait_for_log (9., &|log| log.contains ("LogState] Bye!")));
}

/// https://github.com/KomodoPlatform/atomicDEX-API/issues/886#issuecomment-812489844
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn orders_of_banned_pubkeys_should_not_be_displayed() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );
    // issue sell request on Bob side by setting base/rel price
    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    log!("Ban Bob pubkey on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "ban_pubkey",
        "pubkey": "2cd3021a2197361fb70b862c412bc8e44cff6951fa1de45ceabfdd9b4c520420",
        "reason": "test",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!ban_pubkey: {}", rc.1);

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    assert_eq!(
        alice_orderbook.asks.len(),
        0,
        "Alice RICK/MORTY orderbook must have no asks"
    );

    block_on(mm_alice.wait_for_log(22., |log| {
        log.contains("Pubkey 022cd3021a2197361fb70b862c412bc8e44cff6951fa1de45ceabfdd9b4c520420 is banned")
    }))
    .unwrap();

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
fn log_test_status() { common::log::tests::test_status() }

#[test]
fn log_test_printed_dashboard() { common::log::tests::test_printed_dashboard() }

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_my_balance() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());
    // Enable RICK.
    let json = block_on(enable_electrum(&mm, "RICK", false, DOC_ELECTRUM_ADDRS, None));
    assert_eq!(json.balance, "7.777".parse().unwrap());

    let my_balance = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "my_balance",
        "coin": "RICK",
    })))
    .unwrap();
    assert_eq!(
        my_balance.0,
        StatusCode::OK,
        "RPC «my_balance» failed with status «{}»",
        my_balance.0
    );
    let json: Json = json::from_str(&my_balance.1).unwrap();
    let my_balance = json["balance"].as_str().unwrap();
    assert_eq!(my_balance, "7.777");
    let my_unspendable_balance = json["unspendable_balance"].as_str().unwrap();
    assert_eq!(my_unspendable_balance, "0");
    let my_address = json["address"].as_str().unwrap();
    assert_eq!(my_address, "RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD");
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_p2wpkh_my_balance() {
    let seed = "valley embody about obey never adapt gesture trust screen tube glide bread";

    let coins = json! ([
        {
            "coin": "tBTC",
            "name": "tbitcoin",
            "fname": "tBitcoin",
            "rpcport": 18332,
            "pubtype": 111,
            "p2shtype": 196,
            "wiftype": 239,
            "segwit": true,
            "bech32_hrp": "tb",
            "txfee": 0,
            "estimate_fee_mode": "ECONOMICAL",
            "mm2": 1,
            "required_confirmations": 0,
            "protocol": {
                "type": "UTXO"
            },
            "address_format": {
                "format":"segwit"
            }
        }
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": seed.to_string(),
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    let electrum = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": "tBTC",
        "servers": [{"url":"electrum1.cipig.net:10068"},{"url":"electrum2.cipig.net:10068"},{"url":"electrum3.cipig.net:10068"}],
        "mm2": 1,
        "address_format": {
            "format": "segwit",
        },
    }))).unwrap();
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with {} {}",
        electrum.0,
        electrum.1
    );

    let my_balance = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "my_balance",
        "coin": "tBTC",
    })))
    .unwrap();
    let json: Json = json::from_str(&my_balance.1).unwrap();
    let my_balance = json["balance"].as_str().unwrap();
    assert_eq!(my_balance, "0.002");
    let my_unspendable_balance = json["unspendable_balance"].as_str().unwrap();
    assert_eq!(my_unspendable_balance, "0");
    let my_address = json["address"].as_str().unwrap();
    assert_eq!(my_address, "tb1qssfmay8nnghx7ynlznejnjxn6m4pemz9v7fsxy");
}

#[cfg(not(target_arch = "wasm32"))]
fn check_set_price_fails(mm: &MarketMakerIt, base: &str, rel: &str) {
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "setprice",
        "base": base,
        "rel": rel,
        "price": 0.9,
        "volume": 1,
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!setprice success but should be error: {}",
        rc.1
    );
}

#[cfg(not(target_arch = "wasm32"))]
fn check_buy_fails(mm: &MarketMakerIt, base: &str, rel: &str, vol: f64) {
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "buy",
        "base": base,
        "rel": rel,
        "volume": vol,
        "price": 0.9
    })))
    .unwrap();
    assert!(rc.0.is_server_error(), "!buy success but should be error: {}", rc.1);
}

#[cfg(not(target_arch = "wasm32"))]
fn check_sell_fails(mm: &MarketMakerIt, base: &str, rel: &str, vol: f64) {
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "sell",
        "base": base,
        "rel": rel,
        "volume": vol,
        "price": 0.9
    })))
    .unwrap();
    assert!(rc.0.is_server_error(), "!sell success but should be error: {}", rc.1);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_check_balance_on_order_post() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"ETH","name":"ethereum","protocol":{"type":"ETH"},"rpcport":80},
        {"coin":"JST","name":"jst","protocol":{"type":"ERC20", "protocol_data":{"platform":"ETH","contract_address":"0x996a8aE0304680F6A69b8A9d7C6E37D65AB5AB56"}}}
    ]);

    // start bob and immediately place the order
    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase check balance on order post",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    // Enable coins. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_eth_electrum(
            &mm,
            &["https://mainnet.infura.io/v3/c01c1b4cf66642528547624e1d6d9d6b"],
            None
        )),
    );
    // issue sell request by setting base/rel price

    // Expect error as MORTY balance is 0
    check_set_price_fails(&mm, "MORTY", "RICK");
    // Address has enough RICK, but doesn't have ETH, so setprice call should fail because maker will not have gas to spend ETH taker payment.
    check_set_price_fails(&mm, "RICK", "ETH");
    // Address has enough RICK, but doesn't have ETH, so setprice call should fail because maker will not have gas to spend ERC20 taker payment.
    check_set_price_fails(&mm, "RICK", "JST");

    // Expect error as MORTY balance is 0
    check_buy_fails(&mm, "RICK", "MORTY", 0.1);
    // RICK balance is sufficient, but amount is too small, it will result to dust error from RPC
    check_buy_fails(&mm, "MORTY", "RICK", 0.000001);
    // Address has enough RICK, but doesn't have ETH, so buy call should fail because taker will not have gas to spend ETH maker payment.
    check_buy_fails(&mm, "ETH", "RICK", 0.1);
    // Address has enough RICK, but doesn't have ETH, so buy call should fail because taker will not have gas to spend ERC20 maker payment.
    check_buy_fails(&mm, "JST", "RICK", 0.1);

    // Expect error as MORTY balance is 0
    check_sell_fails(&mm, "MORTY", "RICK", 0.1);
    // RICK balance is sufficient, but amount is too small, the dex fee will result to dust error from RPC
    check_sell_fails(&mm, "RICK", "MORTY", 0.000001);
    // Address has enough RICK, but doesn't have ETH, so buy call should fail because taker will not have gas to spend ETH maker payment.
    check_sell_fails(&mm, "RICK", "ETH", 0.1);
    // Address has enough RICK, but doesn't have ETH, so buy call should fail because taker will not have gas to spend ERC20 maker payment.
    check_sell_fails(&mm, "RICK", "JST", 0.1);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_rpc_password_from_json() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
    ]);

    // do not allow empty password
    let mut err_mm1 = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "",
            "i_am_seed": true,
            "skip_startup_checks": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    block_on(err_mm1.wait_for_log(5., |log| log.contains("rpc_password must not be empty"))).unwrap();

    // do not allow empty password
    let mut err_mm2 = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": {"key":"value"},
            "i_am_seed": true,
            "skip_startup_checks": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    block_on(err_mm2.wait_for_log(5., |log| log.contains("rpc_password must be string"))).unwrap();

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    let electrum_invalid = block_on(mm.rpc(&json! ({
        "userpass": "password1",
        "method": "electrum",
        "coin": "RICK",
        "servers": doc_electrums(),
        "mm2": 1,
    })))
    .unwrap();

    // electrum call must fail if invalid password is provided
    assert!(
        electrum_invalid.0.is_server_error(),
        "RPC «electrum» should have failed with server error, but got «{}», response «{}»",
        electrum_invalid.0,
        electrum_invalid.1
    );

    let electrum = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": "RICK",
        "servers": doc_electrums(),
        "mm2": 1,
    })))
    .unwrap();

    // electrum call must be successful with RPC password from config
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with status «{}», response «{}»",
        electrum.0,
        electrum.1
    );

    let electrum = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": "MORTY",
        "servers": marty_electrums(),
        "mm2": 1,
    })))
    .unwrap();

    // electrum call must be successful with RPC password from config
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with status «{}», response «{}»",
        electrum.0,
        electrum.1
    );

    let orderbook = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();

    // orderbook call must be successful with RPC password from config
    assert_eq!(
        orderbook.0,
        StatusCode::OK,
        "RPC «orderbook» failed with status «{}», response «{}»",
        orderbook.0,
        orderbook.1
    );
}

/// Currently only `withdraw` RPC call supports V2.
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_mmrpc_v2() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());

    let _electrum = block_on(enable_electrum(&mm, "RICK", false, DOC_ELECTRUM_ADDRS, None));

    // no `userpass`
    let withdraw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "method": "withdraw",
        "params": {
            "coin": "RICK",
            "to": "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
            "amount": 0.001,
        },
    })))
    .unwrap();
    assert!(
        withdraw.0.is_client_error(),
        "withdraw should have failed, but got: {}",
        withdraw.1
    );
    let withdraw_error: RpcErrorResponse<()> = json::from_str(&withdraw.1).expect("Expected 'RpcErrorResponse'");
    assert_eq!(withdraw_error.error_type, "UserpassIsNotSet");
    assert!(withdraw_error.error_data.is_none());

    // invalid `userpass`
    let withdraw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": "another password",
        "method": "withdraw",
        "params": {
            "coin": "RICK",
            "to": "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
            "amount": 0.001,
        },
    })))
    .unwrap();
    assert!(
        withdraw.0.is_client_error(),
        "withdraw should have failed, but got: {}",
        withdraw.1
    );
    let withdraw_error: RpcErrorResponse<Json> = json::from_str(&withdraw.1).expect("Expected 'RpcErrorResponse'");
    assert_eq!(withdraw_error.error_type, "UserpassIsInvalid");
    assert!(withdraw_error.error_data.is_some());

    // invalid `mmrpc` version
    let withdraw = block_on(mm.rpc(&json! ({
        "mmrpc": "1.0",
        "userpass": mm.userpass,
        "method": "withdraw",
        "params": {
            "coin": "RICK",
            "to": "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
            "amount": 0.001,
        },
    })))
    .unwrap();
    assert!(
        withdraw.0.is_client_error(),
        "withdraw should have failed, but got: {}",
        withdraw.1
    );
    log!("{:?}", withdraw.1);
    let withdraw_error: RpcErrorResponse<String> = json::from_str(&withdraw.1).expect("Expected 'RpcErrorResponse'");
    assert_eq!(withdraw_error.error_type, "InvalidMmRpcVersion");

    // 'id' = 3
    let withdraw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "withdraw",
        "params": {
            "coin": "RICK",
            "to": "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
            "amount": 0.001,
        },
        "id": 3,
    })))
    .unwrap();
    assert!(withdraw.0.is_success(), "!withdraw: {}", withdraw.1);
    let withdraw_ok: RpcSuccessResponse<TransactionDetails> =
        json::from_str(&withdraw.1).expect("Expected 'RpcSuccessResponse<TransactionDetails>'");
    assert_eq!(withdraw_ok.id, Some(3));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_rpc_password_from_json_no_userpass() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    let electrum = block_on(mm.rpc(&json! ({
        "method": "electrum",
        "coin": "RICK",
        "urls": ["electrum2.cipig.net:10017"],
    })))
    .unwrap();

    // electrum call must return 500 status code
    assert!(
        electrum.0.is_server_error(),
        "RPC «electrum» should have failed with server error, but got «{}», response «{}»",
        electrum.0,
        electrum.1
    );
}

/// Trading test using coins with remote RPC (Electrum, ETH nodes), it needs only ENV variables to be set, coins daemons are not required.
/// Trades few pairs concurrently to speed up the process and also act like "load" test
///
/// Please note that it
#[allow(clippy::too_many_arguments)]
async fn trade_base_rel_electrum(
    bob_priv_key_policy: Mm2InitPrivKeyPolicy,
    alice_priv_key_policy: Mm2InitPrivKeyPolicy,
    bob_path_to_address: Option<StandardHDCoinAddress>,
    alice_path_to_address: Option<StandardHDCoinAddress>,
    pairs: &[(&'static str, &'static str)],
    maker_price: f64,
    taker_price: f64,
    volume: f64,
) {
    let coins = json!([
        rick_conf(),
        morty_conf(),
        eth_testnet_conf(),
        eth_jst_testnet_conf(),
        {"coin":"ZOMBIE","asset":"ZOMBIE","fname":"ZOMBIE (TESTCOIN)","txversion":4,"overwintered":1,"mm2":1,"protocol":{"type":"ZHTLC"},"required_confirmations":0},
    ]);

    let bob_conf = Mm2TestConfForSwap::bob_conf_with_policy(&bob_priv_key_policy, &coins);
    let mut mm_bob = MarketMakerIt::start_async(bob_conf.conf, bob_conf.rpc_password, None)
        .await
        .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    #[cfg(not(target_arch = "wasm32"))]
    {
        log!("Bob log path: {}", mm_bob.log_path.display())
    }

    Timer::sleep(2.).await;

    let alice_conf = Mm2TestConfForSwap::alice_conf_with_policy(&alice_priv_key_policy, &coins, &mm_bob.my_seed_addr());
    let mut mm_alice = MarketMakerIt::start_async(alice_conf.conf, alice_conf.rpc_password, None)
        .await
        .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    #[cfg(not(target_arch = "wasm32"))]
    {
        log!("Alice log path: {}", mm_alice.log_path.display())
    }

    Timer::sleep(2.).await;

    #[cfg(all(feature = "zhtlc-native-tests", not(target_arch = "wasm32")))]
    {
        let bob_passphrase = get_passphrase!(".env.seed", "BOB_PASSPHRASE").unwrap();
        Timer::sleep(1.).await;
        let rmd = rmd160_from_passphrase(&bob_passphrase);
        let bob_zombie_cache_path = mm_bob.folder.join("DB").join(hex::encode(rmd)).join("ZOMBIE_CACHE.db");
        log!("bob_zombie_cache_path {}", bob_zombie_cache_path.display());
        std::fs::copy("./mm2src/coins/for_tests/ZOMBIE_CACHE.db", bob_zombie_cache_path).unwrap();

        let alice_passphrase = get_passphrase!(".env.client", "ALICE_PASSPHRASE").unwrap();
        let rmd = rmd160_from_passphrase(&alice_passphrase);
        let alice_zombie_cache_path = mm_alice
            .folder
            .join("DB")
            .join(hex::encode(rmd))
            .join("ZOMBIE_CACHE.db");
        log!("alice_zombie_cache_path {}", alice_zombie_cache_path.display());

        std::fs::copy("./mm2src/coins/for_tests/ZOMBIE_CACHE.db", alice_zombie_cache_path).unwrap();

        let zombie_bob = enable_z_coin(&mm_bob, "ZOMBIE").await;
        log!("enable ZOMBIE bob {:?}", zombie_bob);
        let zombie_alice = enable_z_coin(&mm_alice, "ZOMBIE").await;
        log!("enable ZOMBIE alice {:?}", zombie_alice);
    }
    // Enable coins on Bob side. Print the replies in case we need the address.
    let rc = enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, bob_path_to_address).await;
    log!("enable_coins (bob): {:?}", rc);

    // Enable coins on Alice side. Print the replies in case we need the address.
    let rc = enable_coins_eth_electrum(&mm_alice, ETH_DEV_NODES, alice_path_to_address).await;
    log!("enable_coins (alice): {:?}", rc);

    let uuids = start_swaps(&mut mm_bob, &mut mm_alice, pairs, maker_price, taker_price, volume).await;

    #[cfg(not(target_arch = "wasm32"))]
    for uuid in uuids.iter() {
        // ensure the swaps are indexed to the SQLite database
        let expected_log = format!("Inserting new swap {} to the SQLite database", uuid);
        mm_alice
            .wait_for_log(5., |log| log.contains(&expected_log))
            .await
            .unwrap();
        mm_bob
            .wait_for_log(5., |log| log.contains(&expected_log))
            .await
            .unwrap()
    }

    wait_for_swaps_finish_and_check_status(&mut mm_bob, &mut mm_alice, &uuids, volume, maker_price).await;

    log!("Waiting 3 seconds for nodes to broadcast their swaps data..");
    Timer::sleep(3.).await;

    #[cfg(all(not(target_arch = "wasm32"), not(feature = "zhtlc-native-tests")))]
    for uuid in uuids.iter() {
        log!("Checking alice status..");
        check_stats_swap_status(&mm_alice, uuid).await;

        log!("Checking bob status..");
        check_stats_swap_status(&mm_bob, uuid).await;
    }

    log!("Checking alice recent swaps..");
    check_recent_swaps(&mm_alice, uuids.len()).await;
    log!("Checking bob recent swaps..");
    check_recent_swaps(&mm_bob, uuids.len()).await;
    for (base, rel) in pairs.iter() {
        log!("Get {}/{} orderbook", base, rel);
        let rc = mm_bob
            .rpc(&json! ({
                "userpass": mm_bob.userpass,
                "method": "orderbook",
                "base": base,
                "rel": rel,
            }))
            .await
            .unwrap();
        assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

        let bob_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
        log!("{}/{} orderbook {:?}", base, rel, bob_orderbook);

        assert_eq!(0, bob_orderbook.bids.len(), "{} {} bids must be empty", base, rel);
        assert_eq!(0, bob_orderbook.asks.len(), "{} {} asks must be empty", base, rel);
    }

    #[cfg(target_arch = "wasm32")]
    {
        const STOP_TIMEOUT_MS: u64 = 1000;

        mm_bob.stop_and_wait_for_ctx_is_dropped(STOP_TIMEOUT_MS).await.unwrap();
        mm_alice
            .stop_and_wait_for_ctx_is_dropped(STOP_TIMEOUT_MS)
            .await
            .unwrap();
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        mm_bob.stop().await.unwrap();
        mm_alice.stop().await.unwrap();
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn trade_test_electrum_and_eth_coins() {
    let bob_policy = Mm2InitPrivKeyPolicy::Iguana;
    let alice_policy = Mm2InitPrivKeyPolicy::GlobalHDAccount;
    let alice_path_to_address = StandardHDCoinAddress {
        account: 0,
        is_change: false,
        address_index: 0,
    };
    let pairs = &[("ETH", "JST")];
    block_on(trade_base_rel_electrum(
        bob_policy,
        alice_policy,
        None,
        Some(alice_path_to_address),
        pairs,
        1.,
        2.,
        0.000001,
    ));
}

#[test]
#[cfg(all(not(target_arch = "wasm32"), feature = "zhtlc-native-tests"))]
fn trade_test_electrum_rick_zombie() {
    let bob_policy = Mm2InitPrivKeyPolicy::Iguana;
    let alice_policy = Mm2InitPrivKeyPolicy::Iguana;
    let pairs = &[("RICK", "ZOMBIE")];
    block_on(trade_base_rel_electrum(
        bob_policy,
        alice_policy,
        None,
        None,
        pairs,
        1.,
        2.,
        0.1,
    ));
}

#[cfg(not(target_arch = "wasm32"))]
fn withdraw_and_send(
    mm: &MarketMakerIt,
    coin: &str,
    from: Option<StandardHDCoinAddress>,
    to: &str,
    enable_res: &HashMap<&'static str, CoinInitResponse>,
    expected_bal_change: &str,
    amount: f64,
) {
    use std::ops::Sub;

    use coins::{TxFeeDetails, WithdrawFrom};

    let from = from.map(WithdrawFrom::HDWalletAddress);
    let withdraw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "withdraw",
        "params": {
            "coin": coin,
            "from": from,
            "to": to,
            "amount": amount,
        },
        "id": 0,
    })))
    .unwrap();

    assert!(withdraw.0.is_success(), "!withdraw: {}", withdraw.1);
    let res: RpcSuccessResponse<TransactionDetails> =
        json::from_str(&withdraw.1).expect("Expected 'RpcSuccessResponse<TransactionDetails>'");
    let tx_details = res.result;

    let from_str = addr_from_enable(enable_res, coin).to_owned();
    let mut expected_bal_change = BigDecimal::from_str(expected_bal_change).expect("!BigDecimal::from_str");

    let fee_details: TxFeeDetails = json::from_value(tx_details.fee_details).unwrap();

    if let TxFeeDetails::Eth(fee_details) = fee_details {
        if coin == "ETH" {
            expected_bal_change = expected_bal_change.sub(fee_details.total_fee);
        }
    }

    assert_eq!(tx_details.to, vec![to.to_owned()]);
    assert_eq!(tx_details.my_balance_change, expected_bal_change);
    // Todo: Should check the from address for withdraws from another HD wallet address when there is an RPC method for addresses
    if from.is_none() {
        assert_eq!(tx_details.from, vec![from_str]);
    }

    let send = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "send_raw_transaction",
        "coin": coin,
        "tx_hex": tx_details.tx_hex,
    })))
    .unwrap();
    assert!(send.0.is_success(), "!{} send: {}", coin, send.1);
    let send_json: Json = json::from_str(&send.1).unwrap();
    assert_eq!(tx_details.tx_hash, send_json["tx_hash"]);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_withdraw_and_send() {
    let alice_passphrase = get_passphrase!(".env.client", "ALICE_PASSPHRASE").unwrap();

    let coins = json! ([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":8923,"txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY_SEGWIT","asset":"MORTY_SEGWIT","txversion":4,"overwintered":1,"segwit":true,"txfee":1000,"protocol":{"type":"UTXO"}},
        eth_testnet_conf(),
        eth_jst_testnet_conf(),
    ]);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8100,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": alice_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // wait until RPC API is active

    // Enable coins. Print the replies in case we need the address.
    let mut enable_res = block_on(enable_coins_eth_electrum(&mm_alice, ETH_DEV_NODES, None));
    enable_res.insert(
        "MORTY_SEGWIT",
        block_on(enable_electrum(
            &mm_alice,
            "MORTY_SEGWIT",
            false,
            MARTY_ELECTRUM_ADDRS,
            None,
        )),
    );

    log!("enable_coins (alice): {:?}", enable_res);
    withdraw_and_send(
        &mm_alice,
        "MORTY",
        None,
        "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
        &enable_res,
        "-0.00101",
        0.001,
    );
    withdraw_and_send(
        &mm_alice,
        "ETH",
        None,
        "0x4b2d0d6c2c785217457B69B922A2A9cEA98f71E9",
        &enable_res,
        "-0.001",
        0.001,
    );
    log!("Wait for the ETH payment to be sent");
    thread::sleep(Duration::from_secs(15));
    withdraw_and_send(
        &mm_alice,
        "JST",
        None,
        "0x4b2d0d6c2c785217457B69B922A2A9cEA98f71E9",
        &enable_res,
        "-0.001",
        0.001,
    );

    // allow to withdraw non-Segwit coin to P2SH addresses
    let withdraw = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "mmrpc": "2.0",
        "method": "withdraw",
        "params": {
            "coin": "MORTY",
            "to": "bUN5nesdt1xsAjCtAaYUnNbQhGqUWwQT1Q",
            "amount": "0.001",
        },
        "id": 0,
    })))
    .unwrap();
    assert!(withdraw.0.is_success(), "MORTY withdraw: {}", withdraw.1);

    // allow to withdraw to P2SH addresses if Segwit flag is true
    let withdraw = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "mmrpc": "2.0",
        "method": "withdraw",
        "params": {
            "coin": "MORTY_SEGWIT",
            "to": "bUN5nesdt1xsAjCtAaYUnNbQhGqUWwQT1Q",
            "amount": "0.001",
        },
        "id": 0,
    })))
    .unwrap();

    assert!(withdraw.0.is_success(), "MORTY_SEGWIT withdraw: {}", withdraw.1);

    // must not allow to withdraw to invalid checksum address
    let withdraw = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "mmrpc": "2.0",
        "method": "withdraw",
        "params": {
            "coin": "ETH",
            "to": "0x4b2d0d6c2c785217457b69b922a2A9cEA98f71E9",
            "amount": "0.001",
        },
        "id": 0,
    })))
    .unwrap();

    assert!(withdraw.0.is_client_error(), "ETH withdraw: {}", withdraw.1);
    let res: RpcErrorResponse<String> = json::from_str(&withdraw.1).unwrap();
    assert_eq!(res.error_type, "InvalidAddress");
    assert!(res.error.contains("Invalid address checksum"));

    // must not allow to withdraw too small amount 0.000005 (less than 0.00001 dust)
    let small_amount = MmNumber::from("0.000005").to_decimal();
    let withdraw = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "mmrpc": "2.0",
        "method": "withdraw",
        "params": {
            "coin": "MORTY",
            "to": "RHzSYSHv3G6J8xL3MyGH3y2gU588VCTC7X",
            "amount": small_amount,
        },
        "id": 0,
    })))
    .unwrap();

    assert!(withdraw.0.is_client_error(), "MORTY withdraw: {}", withdraw.1);
    log!("error: {:?}", withdraw.1);
    let error: RpcErrorResponse<withdraw_error::AmountTooLow> = json::from_str(&withdraw.1).unwrap();
    let threshold = MmNumber::from("0.00001").to_decimal();
    let expected_error = withdraw_error::AmountTooLow {
        amount: small_amount,
        threshold,
    };
    assert_eq!(error.error_type, "AmountTooLow");
    assert_eq!(error.error_data, Some(expected_error));

    block_on(mm_alice.stop()).unwrap();
}

// This test is ignored because it requires refilling addresses with coins
#[test]
#[ignore]
#[cfg(not(target_arch = "wasm32"))]
fn test_withdraw_and_send_hd() {
    const TX_HISTORY: bool = false;
    const PASSPHRASE: &str = "tank abandon bind salon remove wisdom net size aspect direct source fossil";

    let coins = json!([rick_conf(), tbtc_segwit_conf(), eth_testnet_conf()]);

    let conf = Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins);
    let mm_hd = MarketMakerIt::start(conf.conf, conf.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = mm_hd.mm_dump();
    log!("log path: {}", mm_hd.log_path.display());

    let rick = block_on(enable_electrum(&mm_hd, "RICK", TX_HISTORY, RICK_ELECTRUM_ADDRS, None));
    assert_eq!(rick.address, "RXNtAyDSsY3DS3VxTpJegzoHU9bUX54j56");
    let mut rick_enable_res = HashMap::new();
    rick_enable_res.insert("RICK", rick);

    let tbtc_segwit = block_on(enable_electrum(&mm_hd, "tBTC-Segwit", TX_HISTORY, TBTC_ELECTRUMS, None));
    assert_eq!(tbtc_segwit.address, "tb1q7z9vzf8wpp9cks0l4nj5v28zf7jt56kuekegh5");
    let mut tbtc_segwit_enable_res = HashMap::new();
    tbtc_segwit_enable_res.insert("tBTC-Segwit", tbtc_segwit);

    // Enable ETH with HD account 0, change address 0, index 1 to try to withdraw from index 0 which has funds
    let eth = block_on(enable_native(
        &mm_hd,
        "ETH",
        ETH_DEV_NODES,
        Some(StandardHDCoinAddress {
            account: 0,
            is_change: false,
            address_index: 1,
        }),
    ));
    assert_eq!(eth.address, "0xDe841899aB4A22E23dB21634e54920aDec402397");
    let mut eth_enable_res = HashMap::new();
    eth_enable_res.insert("ETH", eth);

    // Withdraw from HD account 0, change address 0, index 1
    let mut from_account_address = StandardHDCoinAddress {
        account: 0,
        is_change: false,
        address_index: 1,
    };

    withdraw_and_send(
        &mm_hd,
        "RICK",
        Some(from_account_address.clone()),
        "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
        &rick_enable_res,
        "-0.00101",
        0.001,
    );

    withdraw_and_send(
        &mm_hd,
        "tBTC-Segwit",
        Some(from_account_address.clone()),
        "tb1q7z9vzf8wpp9cks0l4nj5v28zf7jt56kuekegh5",
        &tbtc_segwit_enable_res,
        "-0.00100144",
        0.001,
    );

    from_account_address.address_index = 0;
    withdraw_and_send(
        &mm_hd,
        "ETH",
        Some(from_account_address),
        "0x4b2d0d6c2c785217457B69B922A2A9cEA98f71E9",
        &eth_enable_res,
        "-0.001",
        0.001,
    );
    log!("Wait for the ETH payment to be sent");
    thread::sleep(Duration::from_secs(15));

    block_on(mm_hd.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_tbtc_withdraw_to_cashaddresses_should_fail() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";

    let coins = json! ([
        {
            "coin": "tBTC",
            "name": "tbitcoin",
            "fname": "tBitcoin",
            "rpcport": 18332,
            "pubtype": 111,
            "p2shtype": 196,
            "wiftype": 239,
            "segwit": true,
            "bech32_hrp": "tb",
            "txfee": 1000,
            "mm2": 1,
            "required_confirmations": 0,
            "protocol": {
                "type": "UTXO"
            }
        }
    ]);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8100,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": seed.to_string(),
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // wait until RPC API is active

    // Enable coins. Print the replies in case we need the address.
    let electrum = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "electrum",
        "coin": "tBTC",
        "servers": [{"url":"electrum1.cipig.net:10068"},{"url":"electrum2.cipig.net:10068"},{"url":"electrum3.cipig.net:10068"}],
        "mm2": 1,
    }))).unwrap();
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with {} {}",
        electrum.0,
        electrum.1
    );
    log!("enable_coins (alice): {:?}", electrum);

    let electrum_response: CoinInitResponse = json::from_str(&electrum.1).expect("Expected 'CoinInitResponse'");
    let mut enable_res = HashMap::new();
    enable_res.insert("tBTC", electrum_response);

    // Send from BTC Legacy Address to Cashaddress should fail
    let withdraw = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "withdraw",
        "coin": "tBTC",
        "to": "bchtest:qqgp9xh3435xamv7ghct8emer2s2erzj8gx3gnhwkq",
        "amount": 0.00001,
    })))
    .unwrap();

    assert!(withdraw.0.is_server_error(), "tBTC withdraw: {}", withdraw.1);
    log!("{:?}", withdraw.1);

    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_withdraw_legacy() {
    let (alice_file_passphrase, _alice_file_userpass) = from_env_file(slurp(&".env.client").unwrap());

    let alice_passphrase = var("ALICE_PASSPHRASE")
        .ok()
        .or(alice_file_passphrase)
        .expect("No ALICE_PASSPHRASE or .env.client/ALICE_PASSPHRASE");

    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":8923,"txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY_SEGWIT","asset":"MORTY_SEGWIT","txversion":4,"overwintered":1,"segwit":true,"txfee":1000,"protocol":{"type":"UTXO"}}
    ]);

    let mm_alice = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 8100,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": alice_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // wait until RPC API is active

    // Enable coins. Print the replies in case we need the address.
    let mut enable_res = block_on(enable_coins_rick_morty_electrum(&mm_alice));
    enable_res.insert(
        "MORTY_SEGWIT",
        block_on(enable_electrum(
            &mm_alice,
            "MORTY_SEGWIT",
            false,
            MARTY_ELECTRUM_ADDRS,
            None,
        )),
    );
    log!("enable_coins (alice): {:?}", enable_res);

    let withdraw = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "withdraw",
        "coin": "MORTY",
        "to": "RJTYiYeJ8eVvJ53n2YbrVmxWNNMVZjDGLh",
        "amount": 0.001,
    })))
    .unwrap();
    assert!(withdraw.0.is_success(), "MORTY withdraw: {}", withdraw.1);
    let _: TransactionDetails = json::from_str(&withdraw.1).expect("Expected 'TransactionDetails'");

    // allow to withdraw non-Segwit coin to P2SH addresses
    let withdraw = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "withdraw",
        "coin": "MORTY",
        "to": "bUN5nesdt1xsAjCtAaYUnNbQhGqUWwQT1Q",
        "amount": "0.001",
    })))
    .unwrap();
    assert!(withdraw.0.is_success(), "MORTY withdraw: {}", withdraw.1);

    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_withdraw_segwit() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";

    let coins = json!([
        {
            "coin": "tBTC",
            "name": "tbitcoin",
            "fname": "tBitcoin",
            "rpcport": 18332,
            "pubtype": 111,
            "p2shtype": 196,
            "wiftype": 239,
            "segwit": true,
            "bech32_hrp": "tb",
            "txfee": 0,
            "estimate_fee_mode": "ECONOMICAL",
            "mm2": 1,
            "required_confirmations": 0,
            "protocol": {
                "type": "UTXO"
            },
            "address_format": {
                "format":"segwit"
            }
        }
    ]);

    let mm_alice = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 8100,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": seed.to_string(),
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // wait until RPC API is active

    // Enable coins. Print the replies in case we need the address.
    let electrum = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "electrum",
        "coin": "tBTC",
        "servers": [{"url":"electrum1.cipig.net:10068"},{"url":"electrum2.cipig.net:10068"},{"url":"electrum3.cipig.net:10068"}],
        "mm2": 1,
        "address_format": {
            "format": "segwit",
        },
    }))).unwrap();
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with {} {}",
        electrum.0,
        electrum.1
    );
    log!("enable_coins (alice): {:?}", electrum);

    let withdraw = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "withdraw",
        "coin": "tBTC",
        "to": "tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
        "amount": 0.00001,
    })))
    .unwrap();
    assert!(withdraw.0.is_success(), "tBTC withdraw: {}", withdraw.1);
    let _: TransactionDetails = json::from_str(&withdraw.1).expect("Expected 'TransactionDetails'");

    // must not allow to withdraw to addresses with different hrp
    // Invalid human-readable part test vector https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#test-vectors
    let withdraw = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "withdraw",
        "coin": "tBTC",
        "to": "ltc1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
        "amount": 0.00001,
    })))
    .unwrap();

    assert!(withdraw.0.is_server_error(), "tBTC withdraw: {}", withdraw.1);
    log!("{:?}", withdraw.1);
    let withdraw_error: Json = json::from_str(&withdraw.1).unwrap();
    withdraw_error["error"]
        .as_str()
        .expect("Expected 'error' field")
        .contains("Address hrp ltc is not a valid hrp for tBTC");
    assert!(withdraw_error.get("error_path").is_none());
    assert!(withdraw_error.get("error_trace").is_none());
    assert!(withdraw_error.get("error_type").is_none());
    assert!(withdraw_error.get("error_data").is_none());

    // Withdraw to taproot addresses should fail
    let withdraw = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "withdraw",
        "coin": "tBTC",
        "to": "tb1p6h5fuzmnvpdthf5shf0qqjzwy7wsqc5rhmgq2ks9xrak4ry6mtrscsqvzp",
        "amount": 0.00001,
    })))
    .unwrap();

    assert!(withdraw.0.is_server_error(), "tBTC withdraw: {}", withdraw.1);
    log!("{:?}", withdraw.1);
    let withdraw_error: Json = json::from_str(&withdraw.1).unwrap();
    assert!(withdraw_error["error"]
        .as_str()
        .expect("Expected 'error' field")
        .contains("address variant/format Bech32m is not supported yet"));

    block_on(mm_alice.stop()).unwrap();
}

/// Ensure that swap status return the 404 status code if swap is not found
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_swap_status() {
    let coins = json! ([{"coin":"RICK","asset":"RICK"},]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8100,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "some passphrase",
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let my_swap = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "my_swap_status",
        "params": {
            "uuid": new_uuid(),
        }
    })))
    .unwrap();

    assert!(my_swap.0.is_server_error(), "!not found status code: {}", my_swap.1);

    let stats_swap = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "stats_swap_status",
        "params": {
            "uuid": new_uuid(),
        }
    })))
    .unwrap();

    assert!(
        stats_swap.0.is_server_error(),
        "!not found status code: {}",
        stats_swap.1
    );
}

/// Ensure that setprice/buy/sell calls deny base == rel
/// https://github.com/artemii235/SuperNET/issues/363
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_order_errors_when_base_equal_rel() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    block_on(enable_electrum(&mm, "RICK", false, DOC_ELECTRUM_ADDRS, None));

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "RICK",
        "price": 0.9
    })))
    .unwrap();
    assert!(rc.0.is_server_error(), "setprice should have failed, but got {:?}", rc);

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "buy",
        "base": "RICK",
        "rel": "RICK",
        "price": 0.9,
        "relvolume": 0.1,
    })))
    .unwrap();
    assert!(rc.0.is_server_error(), "buy should have failed, but got {:?}", rc);

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "sell",
        "base": "RICK",
        "rel": "RICK",
        "price": 0.9,
        "basevolume": 0.1,
    })))
    .unwrap();
    assert!(rc.0.is_server_error(), "sell should have failed, but got {:?}", rc);
}

#[cfg(not(target_arch = "wasm32"))]
fn startup_passphrase(passphrase: &str, expected_address: &str) {
    let coins = json!([
        {"coin":"KMD","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    #[cfg(not(target_arch = "wasm32"))]
    {
        log!("Log path: {}", mm.log_path.display())
    }
    let enable = block_on(enable_electrum(&mm, "KMD", false, &["electrum1.cipig.net:10001"], None));
    assert_eq!(expected_address, enable.address);
    block_on(mm.stop()).unwrap();
}

/// MM2 should detect if passphrase is WIF or 0x-prefixed hex encoded privkey and parse it properly.
/// https://github.com/artemii235/SuperNET/issues/396
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_startup_passphrase() {
    // seed phrase
    startup_passphrase("bob passphrase", "RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD");

    // WIF
    assert!(key_pair_from_seed("UvCjJf4dKSs2vFGVtCnUTAhR5FTZGdg43DDRa9s7s5DV1sSDX14g").is_ok());
    startup_passphrase(
        "UvCjJf4dKSs2vFGVtCnUTAhR5FTZGdg43DDRa9s7s5DV1sSDX14g",
        "RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD",
    );
    // WIF, Invalid network version
    assert!(key_pair_from_seed("92Qba5hnyWSn5Ffcka56yMQauaWY6ZLd91Vzxbi4a9CCetaHtYj").is_err());
    // WIF, not compressed
    assert!(key_pair_from_seed("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf").is_err());

    // 0x prefixed hex
    assert!(key_pair_from_seed("0xb8c774f071de08c7fd8f62b97f1a5726f6ce9f1bcf141b70b86689254ed6714e").is_ok());
    startup_passphrase(
        "0xb8c774f071de08c7fd8f62b97f1a5726f6ce9f1bcf141b70b86689254ed6714e",
        "RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD",
    );
    // Out of range, https://en.bitcoin.it/wiki/Private_key#Range_of_valid_ECDSA_private_keys
    assert!(key_pair_from_seed("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").is_err());
}

/// https://github.com/artemii235/SuperNET/issues/398
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_cancel_order() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);
    let bob_passphrase = "bob passphrase";

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    thread::sleep(Duration::from_secs(2));
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    log!("Issue sell request on Bob side by setting base/rel price…");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let setprice_json: Json = json::from_str(&rc.1).unwrap();
    log!("{:?}", setprice_json);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    thread::sleep(Duration::from_secs(2));

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // Enable coins on Alice side. Print the replies in case we need the "address".
    log!(
        "enable_coins (alice): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_alice))
    );

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    assert_eq!(
        alice_orderbook.asks.len(),
        1,
        "Alice RICK/MORTY orderbook must have exactly 1 ask"
    );

    let cancel_rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "cancel_order",
        "uuid": setprice_json["result"]["uuid"],
    })))
    .unwrap();
    assert!(cancel_rc.0.is_success(), "!cancel_order: {}", rc.1);
    let uuid: Uuid = json::from_value(setprice_json["result"]["uuid"].clone()).unwrap();
    let order_path = mm_bob.folder.join(format!(
        "DB/{}/ORDERS/MY/MAKER/{}.json",
        hex::encode(rmd160_from_passphrase(bob_passphrase)),
        uuid
    ));
    assert!(!order_path.exists());

    let pause = 3;
    log!("Waiting ({} seconds) for Bob to cancel the order…", pause);
    thread::sleep(Duration::from_secs(pause));

    // Bob orderbook must show no orders
    log!("Get RICK/MORTY orderbook on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let bob_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
    log!("Bob orderbook {:?}", bob_orderbook);
    assert_eq!(bob_orderbook.asks.len(), 0, "Bob RICK/MORTY asks are not empty");

    // Alice orderbook must show no orders
    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    assert_eq!(alice_orderbook.asks.len(), 0, "Alice RICK/MORTY asks are not empty");
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_cancel_all_orders() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    let bob_passphrase = "bob passphrase";
    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    log!("Issue sell request on Bob side by setting base/rel price…");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let setprice_json: Json = json::from_str(&rc.1).unwrap();
    log!("{:?}", setprice_json);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // Enable coins on Alice side. Print the replies in case we need the "address".
    log!(
        "enable_coins (alice): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_alice))
    );

    log!("Give Alice 3 seconds to import the order…");
    thread::sleep(Duration::from_secs(3));

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Alice RICK/MORTY orderbook must have exactly 1 ask");

    let cancel_rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "cancel_all_orders",
        "cancel_by": {
            "type": "All",
        }
    })))
    .unwrap();
    assert!(cancel_rc.0.is_success(), "!cancel_all_orders: {}", rc.1);
    let uuid: Uuid = json::from_value(setprice_json["result"]["uuid"].clone()).unwrap();
    let order_path = mm_bob.folder.join(format!(
        "DB/{}/ORDERS/MY/MAKER/{}.json",
        hex::encode(rmd160_from_passphrase(bob_passphrase)),
        uuid
    ));
    assert!(!order_path.exists());

    let pause = 3;
    log!("Waiting ({} seconds) for Bob to cancel the order…", pause);
    thread::sleep(Duration::from_secs(pause));

    // Bob orderbook must show no orders
    log!("Get RICK/MORTY orderbook on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let bob_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Bob orderbook {:?}", bob_orderbook);
    let asks = bob_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 0, "Bob RICK/MORTY asks are not empty");

    // Alice orderbook must show no orders
    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 0, "Alice RICK/MORTY asks are not empty");
}

/// https://github.com/artemii235/SuperNET/issues/367
/// Electrum requests should success if at least 1 server successfully connected,
/// all others might end up with DNS resolution errors, TCP connection errors, etc.
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_electrum_enable_conn_errors() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","protocol":{"type":"UTXO"}},
    ]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Using working servers and few else with random ports to trigger "connection refused"
    block_on(enable_electrum(
        &mm_bob,
        "RICK",
        false,
        &[
            "electrum3.cipig.net:10020",
            "electrum2.cipig.net:10020",
            "electrum1.cipig.net:10020",
            "electrum1.cipig.net:60020",
            "electrum1.cipig.net:60021",
        ],
        None,
    ));
    // use random domain name to trigger name is not resolved
    block_on(enable_electrum(
        &mm_bob,
        "MORTY",
        false,
        &[
            "electrum3.cipig.net:10021",
            "electrum2.cipig.net:10021",
            "electrum1.cipig.net:10021",
            "random-electrum-domain-name1.net:60020",
            "random-electrum-domain-name2.net:60020",
        ],
        None,
    ));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_order_should_not_be_displayed_when_node_is_down() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","protocol":{"type":"UTXO"}},
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    let electrum_rick = block_on(enable_electrum(&mm_bob, "RICK", false, DOC_ELECTRUM_ADDRS, None));
    log!("Bob enable RICK {:?}", electrum_rick);

    let electrum_morty = block_on(enable_electrum(&mm_bob, "MORTY", false, MARTY_ELECTRUM_ADDRS, None));
    log!("Bob enable MORTY {:?}", electrum_morty);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
            "maker_order_timeout": 5,
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    let electrum_rick = block_on(enable_electrum(&mm_alice, "RICK", false, DOC_ELECTRUM_ADDRS, None));
    log!("Alice enable RICK {:?}", electrum_rick);

    let electrum_morty = block_on(enable_electrum(&mm_alice, "MORTY", false, MARTY_ELECTRUM_ADDRS, None));
    log!("Alice enable MORTY {:?}", electrum_morty);

    // issue sell request on Bob side by setting base/rel price
    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    thread::sleep(Duration::from_secs(2));

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Alice RICK/MORTY orderbook must have exactly 1 ask");

    block_on(mm_bob.stop()).unwrap();
    thread::sleep(Duration::from_secs(6));

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 0, "Alice RICK/MORTY orderbook must have zero asks");

    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_own_orders_should_not_be_removed_from_orderbook() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","protocol":{"type":"UTXO"}},
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
            "maker_order_timeout": 5,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    let electrum_rick = block_on(enable_electrum(&mm_bob, "RICK", false, DOC_ELECTRUM_ADDRS, None));
    log!("Bob enable RICK {:?}", electrum_rick);

    let electrum_morty = block_on(enable_electrum(&mm_bob, "MORTY", false, MARTY_ELECTRUM_ADDRS, None));
    log!("Bob enable MORTY {:?}", electrum_morty);

    // issue sell request on Bob side by setting base/rel price
    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    thread::sleep(Duration::from_secs(6));

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let bob_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Bob orderbook {:?}", bob_orderbook);
    let asks = bob_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Bob RICK/MORTY orderbook must have exactly 1 ask");

    block_on(mm_bob.stop()).unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
fn check_priv_key(mm: &MarketMakerIt, coin: &str, expected_priv_key: &str) {
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "show_priv_key",
        "coin": coin
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!show_priv_key: {}", rc.1);
    let privkey: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(privkey["result"]["priv_key"], Json::from(expected_priv_key))
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/519#issuecomment-589149811
fn test_show_priv_key() {
    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    log!(
        "enable_coins: {:?}",
        block_on(enable_coins_eth_electrum(&mm, ETH_DEV_NODES, None))
    );

    check_priv_key(&mm, "RICK", "UvCjJf4dKSs2vFGVtCnUTAhR5FTZGdg43DDRa9s7s5DV1sSDX14g");
    check_priv_key(
        &mm,
        "ETH",
        "0xb8c774f071de08c7fd8f62b97f1a5726f6ce9f1bcf141b70b86689254ed6714e",
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_electrum_and_enable_response() {
    let coins = json! ([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"},"mature_confirmations":101},
        {"coin":"ETH","name":"ethereum","protocol":{"type":"ETH"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());

    let electrum_rick = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": "RICK",
        "servers": doc_electrums(),
        "mm2": 1,
        "required_confirmations": 10,
        "requires_notarization": true
    })))
    .unwrap();
    assert_eq!(
        electrum_rick.0,
        StatusCode::OK,
        "RPC «electrum» failed with {} {}",
        electrum_rick.0,
        electrum_rick.1
    );
    let rick_response: Json = json::from_str(&electrum_rick.1).unwrap();
    assert_eq!(rick_response["unspendable_balance"], Json::from("0"));
    assert_eq!(rick_response["required_confirmations"], Json::from(10));
    assert_eq!(rick_response["requires_notarization"], Json::from(true));
    assert_eq!(rick_response["mature_confirmations"], Json::from(101));

    // should change requires notarization at runtime
    let requires_nota_rick = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "set_requires_notarization",
        "coin": "RICK",
        "requires_notarization": false
    })))
    .unwrap();

    assert_eq!(
        requires_nota_rick.0,
        StatusCode::OK,
        "RPC «set_requires_notarization» failed with {} {}",
        requires_nota_rick.0,
        requires_nota_rick.1
    );
    let requires_nota_rick_response: Json = json::from_str(&requires_nota_rick.1).unwrap();
    assert_eq!(
        requires_nota_rick_response["result"]["requires_notarization"],
        Json::from(false)
    );

    let enable_eth = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "enable",
        "coin": "ETH",
        "urls": ETH_DEV_NODES,
        "mm2": 1,
        "swap_contract_address": ETH_DEV_SWAP_CONTRACT,
        "required_confirmations": 10,
        "requires_notarization": true
    })))
    .unwrap();
    assert_eq!(
        enable_eth.0,
        StatusCode::OK,
        "RPC «enable» failed with {} {}",
        enable_eth.0,
        enable_eth.1
    );
    let eth_response: Json = json::from_str(&enable_eth.1).unwrap();
    assert_eq!(rick_response["unspendable_balance"], Json::from("0"));
    assert_eq!(eth_response["required_confirmations"], Json::from(10));
    // requires_notarization doesn't take any effect on ETH/ERC20 coins
    assert_eq!(eth_response["requires_notarization"], Json::from(false));
    // check if there is no `mature_confirmations` field
    assert_eq!(eth_response.get("mature_confirmations"), None);
}

#[cfg(not(target_arch = "wasm32"))]
fn check_too_low_volume_order_creation_fails(mm: &MarketMakerIt, base: &str, rel: &str) {
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "setprice",
        "base": base,
        "rel": rel,
        "price": "1",
        "volume": "0.00000099",
        "cancel_previous": false,
    })))
    .unwrap();
    assert!(!rc.0.is_success(), "setprice success, but should be error {}", rc.1);

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "setprice",
        "base": base,
        "rel": rel,
        "price": "0.00000000000000000099",
        "volume": "1",
        "cancel_previous": false,
    })))
    .unwrap();
    assert!(!rc.0.is_success(), "setprice success, but should be error {}", rc.1);

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "sell",
        "base": base,
        "rel": rel,
        "price": "1",
        "volume": "0.00000099",
    })))
    .unwrap();
    assert!(!rc.0.is_success(), "sell success, but should be error {}", rc.1);

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "buy",
        "base": base,
        "rel": rel,
        "price": "1",
        "volume": "0.00000099",
    })))
    .unwrap();
    assert!(!rc.0.is_success(), "buy success, but should be error {}", rc.1);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/481
fn setprice_buy_sell_too_low_volume() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());

    let enable = block_on(enable_coins_eth_electrum(&mm, ETH_DEV_NODES, None));
    log!("{:?}", enable);

    check_too_low_volume_order_creation_fails(&mm, "MORTY", "ETH");
    check_too_low_volume_order_creation_fails(&mm, "ETH", "MORTY");
    check_too_low_volume_order_creation_fails(&mm, "JST", "MORTY");
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_fill_or_kill_taker_order_should_not_transform_to_maker() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob ETH/JST sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "order_type": {
            "type": "FillOrKill"
        },
        "timeout": 2,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let sell_json: Json = json::from_str(&rc.1).unwrap();
    let order_type = sell_json["result"]["order_type"]["type"].as_str();
    assert_eq!(order_type, Some("FillOrKill"));

    log!("Wait for 4 seconds for Bob order to be cancelled");
    thread::sleep(Duration::from_secs(4));

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
    let my_orders: Json = json::from_str(&rc.1).unwrap();
    let my_maker_orders: HashMap<String, Json> = json::from_value(my_orders["result"]["maker_orders"].clone()).unwrap();
    let my_taker_orders: HashMap<String, Json> = json::from_value(my_orders["result"]["taker_orders"].clone()).unwrap();
    assert!(my_maker_orders.is_empty(), "maker_orders must be empty");
    assert!(my_taker_orders.is_empty(), "taker_orders must be empty");
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_gtc_taker_order_should_transform_to_maker() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob ETH/JST sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "order_type": {
            "type": "GoodTillCancelled"
        },
        "timeout": 2,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let rc_json: Json = json::from_str(&rc.1).unwrap();
    let uuid: Uuid = json::from_value(rc_json["result"]["uuid"].clone()).unwrap();

    log!("Wait for 4 seconds for Bob order to be converted to maker");
    thread::sleep(Duration::from_secs(4));

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
    let my_orders: Json = json::from_str(&rc.1).unwrap();
    let my_maker_orders: HashMap<String, Json> = json::from_value(my_orders["result"]["maker_orders"].clone()).unwrap();
    let my_taker_orders: HashMap<String, Json> = json::from_value(my_orders["result"]["taker_orders"].clone()).unwrap();
    assert_eq!(1, my_maker_orders.len(), "maker_orders must have exactly 1 order");
    assert!(my_taker_orders.is_empty(), "taker_orders must be empty");
    let order_path = mm_bob.folder.join(format!(
        "DB/{}/ORDERS/MY/MAKER/{}.json",
        hex::encode(rmd160_from_passphrase(&bob_passphrase)),
        uuid
    ));
    log!("Order path {}", order_path.display());
    assert!(order_path.exists());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_set_price_must_save_order_to_db() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob ETH/JST sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let rc_json: Json = json::from_str(&rc.1).unwrap();
    let uuid: Uuid = json::from_value(rc_json["result"]["uuid"].clone()).unwrap();
    let order_path = mm_bob.folder.join(format!(
        "DB/{}/ORDERS/MY/MAKER/{}.json",
        hex::encode(rmd160_from_passphrase(&bob_passphrase)),
        uuid
    ));
    assert!(order_path.exists());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_set_price_response_format() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob ETH/JST sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let rc_json: Json = json::from_str(&rc.1).unwrap();
    let _: BigDecimal = json::from_value(rc_json["result"]["max_base_vol"].clone()).unwrap();
    let _: BigDecimal = json::from_value(rc_json["result"]["min_base_vol"].clone()).unwrap();
    let _: BigDecimal = json::from_value(rc_json["result"]["price"].clone()).unwrap();

    let _: BigRational = json::from_value(rc_json["result"]["max_base_vol_rat"].clone()).unwrap();
    let _: BigRational = json::from_value(rc_json["result"]["min_base_vol_rat"].clone()).unwrap();
    let _: BigRational = json::from_value(rc_json["result"]["price_rat"].clone()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
// https://github.com/KomodoPlatform/atomicDEX-API/issues/635
fn set_price_with_cancel_previous_should_broadcast_cancelled_message() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    let set_price_json = json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    });
    log!("Issue sell request on Bob side by setting base/rel price…");
    let rc = block_on(mm_bob.rpc(&set_price_json)).unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // Enable coins on Alice side. Print the replies in case we need the "address".
    log!(
        "enable_coins (alice): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_alice))
    );

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Alice RICK/MORTY orderbook must have exactly 1 ask");

    log!("Issue sell request again on Bob side by setting base/rel price…");
    let rc = block_on(mm_bob.rpc(&set_price_json)).unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let pause = 2;
    log!("Waiting ({} seconds) for Bob to broadcast messages…", pause);
    thread::sleep(Duration::from_secs(pause));

    // Bob orderbook must show 1 order
    log!("Get RICK/MORTY orderbook on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let bob_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Bob orderbook {:?}", bob_orderbook);
    let asks = bob_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Bob RICK/MORTY orderbook must have exactly 1 ask");

    // Alice orderbook must have 1 order
    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Alice RICK/MORTY orderbook must have exactly 1 ask");
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_batch_requests() {
    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    let batch_json = json!([
        {
            "userpass": mm_bob.userpass,
            "method": "electrum",
            "coin": "RICK",
            "servers": doc_electrums(),
            "mm2": 1,
        },
        {
            "userpass": mm_bob.userpass,
            "method": "electrum",
            "coin": "MORTY",
            "servers": doc_electrums(),
            "mm2": 1,
        },
        {
            "userpass": "error",
            "method": "electrum",
            "coin": "MORTY",
            "servers": marty_electrums(),
            "mm2": 1,
        },
    ]);

    let rc = block_on(mm_bob.rpc(&batch_json)).unwrap();
    assert!(rc.0.is_success(), "!batch: {}", rc.1);
    log!("{}", rc.1);
    let responses = json::from_str::<Vec<Json>>(&rc.1).unwrap();
    assert_eq!(responses[0]["coin"], Json::from("RICK"));
    assert_eq!(
        responses[0]["address"],
        Json::from("RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD")
    );

    assert_eq!(responses[1]["coin"], Json::from("MORTY"));
    assert_eq!(
        responses[1]["address"],
        Json::from("RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD")
    );

    assert!(responses[2]["error"].as_str().unwrap().contains("Userpass is invalid!"));
}

#[cfg(not(target_arch = "wasm32"))]
fn request_metrics(mm: &MarketMakerIt) -> MetricsJson {
    let (status, metrics, _headers) = block_on(mm.rpc(&json!({ "method": "metrics"}))).unwrap();
    assert_eq!(status, StatusCode::OK, "RPC «metrics» failed with status «{}»", status);
    json::from_str(&metrics).unwrap()
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_metrics_method() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "face pin block number add byte put seek mime test note password sin tab multiple",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    let _electrum = block_on(enable_electrum(&mm, "RICK", false, DOC_ELECTRUM_ADDRS, None));

    let metrics = request_metrics(&mm);
    assert!(!metrics.metrics.is_empty());

    log!("Received metrics:");
    log!("{:?}", metrics);

    find_metrics_in_json(metrics, "rpc_client.traffic.out", &[("coin", "RICK")])
        .expect(r#"Couldn't find a metric with key = "traffic.out" and label: coin = "RICK" in received json"#);
}

#[test]
#[ignore]
#[cfg(not(target_arch = "wasm32"))]
fn test_electrum_tx_history() {
    fn get_tx_history_request_count(mm: &MarketMakerIt) -> u64 {
        let metrics = request_metrics(mm);
        match find_metrics_in_json(metrics, "tx.history.request.count", &[
            ("coin", "RICK"),
            ("method", "blockchain.scripthash.get_history"),
        ])
        .unwrap()
        {
            MetricType::Counter { value, .. } => value,
            _ => panic!("tx.history.request.count should be a counter"),
        }
    }

    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
    ]);

    let mut mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "face pin block number add byte put seek mime test note password sin tab multiple",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
            "metrics_interval": 30.
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    // Enable RICK electrum client with tx_history loop.
    let electrum = block_on(enable_electrum(
        &mm,
        "RICK",
        true,
        &[
            "electrum1.cipig.net:10017",
            "electrum2.cipig.net:10017",
            "electrum3.cipig.net:10017",
        ],
        None,
    ));

    // Wait till tx_history will not be loaded
    block_on(mm.wait_for_log(500., |log| log.contains("history has been loaded successfully"))).unwrap();

    // tx_history is requested every 30 seconds, wait another iteration
    thread::sleep(Duration::from_secs(31));

    // Balance is not changed, therefore tx_history shouldn't be reloaded.
    // Request metrics and check if the MarketMaker has requested tx_history only once
    assert_eq!(get_tx_history_request_count(&mm), 1);

    // make a transaction to change balance
    let mut enable_res = HashMap::new();
    enable_res.insert("RICK", electrum);
    log!("enable_coins: {:?}", enable_res);
    withdraw_and_send(
        &mm,
        "RICK",
        None,
        "RRYmiZSDo3UdHHqj1rLKf8cbJroyv9NxXw",
        &enable_res,
        "-0.00001",
        0.001,
    );

    // Wait another iteration
    thread::sleep(Duration::from_secs(31));

    // tx_history should be reloaded on next loop iteration
    assert_eq!(get_tx_history_request_count(&mm), 2);
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
fn spin_n_nodes(seednodes: &[&str], coins: &Json, n: usize) -> Vec<(MarketMakerIt, RaiiDump, RaiiDump)> {
    let mut mm_nodes = Vec::with_capacity(n);
    for i in 0..n {
        let mut mm = MarketMakerIt::start(
            json! ({
                "gui": "nogui",
                "netid": 9998,
                "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
                "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
                "passphrase": format!("alice passphrase {}", i),
                "coins": coins,
                "seednodes": seednodes,
                "rpc_password": "pass",
            }),
            "pass".into(),
            None,
        )
        .unwrap();

        let (alice_dump_log, alice_dump_dashboard) = mm.mm_dump();
        log!("Alice {} log path: {}", i, mm.log_path.display());
        for seednode in seednodes.iter() {
            block_on(mm.wait_for_log(22., |log| log.contains(&format!("Dialed {}", seednode)))).unwrap();
        }
        mm_nodes.push((mm, alice_dump_log, alice_dump_dashboard));
    }
    mm_nodes
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_convert_utxo_address() {
    let coins = json!([
        {"coin":"BCH","pubtype":0,"p2shtype":5,"mm2":1,"fork_id": "0x40","protocol":{"type":"UTXO"},
         "address_format":{"format":"cashaddress","network":"bitcoincash"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "face pin block number add byte put seek mime test note password sin tab multiple",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    let _electrum = block_on(enable_electrum(&mm, "BCH", false, T_BCH_ELECTRUMS, None));

    // test standard to cashaddress
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "BCH",
        "from": "1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM",
        "to_address_format":{"format":"cashaddress","network":"bitcoincash"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "bitcoincash:qzxqqt9lh4feptf0mplnk58gnajfepzwcq9f2rxk55",
        },
    });
    assert_eq!(actual, expected);

    // test cashaddress to standard
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "BCH",
        "from": "bitcoincash:qzxqqt9lh4feptf0mplnk58gnajfepzwcq9f2rxk55",
        "to_address_format":{"format":"standard"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM",
        },
    });
    assert_eq!(actual, expected);

    // test standard to standard
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "BCH",
        "from": "1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM",
        "to_address_format":{"format":"standard"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM",
        },
    });
    assert_eq!(actual, expected);

    // test invalid address
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "BCH",
        "from": "0000000000000000000000000000000000",
        "to_address_format":{"format":"standard"},
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!convertaddress success but should be error: {}",
        rc.1
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_convert_segwit_address() {
    let coins = json! ([
        {
            "coin": "tBTC",
            "name": "tbitcoin",
            "fname": "tBitcoin",
            "rpcport": 18332,
            "pubtype": 111,
            "p2shtype": 196,
            "wiftype": 239,
            "segwit": true,
            "bech32_hrp": "tb",
            "txfee": 1000,
            "mm2": 1,
            "required_confirmations": 0,
            "protocol": {
                "type": "UTXO"
            }
        }
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "face pin block number add byte put seek mime test note password sin tab multiple",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    let _electrum = block_on(enable_electrum(
        &mm,
        "tBTC",
        false,
        &[
            "electrum1.cipig.net:10068",
            "electrum2.cipig.net:10068",
            "electrum3.cipig.net:10068",
        ],
        None,
    ));

    // test standard to segwit
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "tBTC",
        "from": "mqWYEGxLeK843n3xMTe8EWTFPyoSZjtUXb",
        "to_address_format":{"format":"segwit"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
        },
    });
    assert_eq!(actual, expected);

    // test segwit to standard
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "tBTC",
        "from": "tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
        "to_address_format":{"format":"standard"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "mqWYEGxLeK843n3xMTe8EWTFPyoSZjtUXb",
        },
    });
    assert_eq!(actual, expected);

    // test invalid tBTC standard address
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "tBTC",
        "from": "1AzawDsMqHgoGfaLdtfkQbEvXzCjk5oyFx",
        "to_address_format":{"format":"segwit"},
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!convertaddress success but should be error: {}",
        rc.1
    );
    assert!(rc.1.contains("invalid address prefix"));

    // test invalid tBTC segwit address
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "tBTC",
        "from": "ltc1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
        "to_address_format":{"format":"standard"},
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!convertaddress success but should be error: {}",
        rc.1
    );
    assert!(rc.1.contains("Cannot determine format"));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_convert_eth_address() {
    let coins = json!([
        {"coin":"ETH","name":"ethereum","protocol":{"type":"ETH"}},
    ]);

    // start mm and immediately place the order
    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    block_on(enable_native(&mm, "ETH", ETH_DEV_NODES, None));

    // test single-case to mixed-case
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "ETH",
        "from": "0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359",
        "to_address_format":{"format":"mixedcase"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        },
    });
    assert_eq!(actual, expected);

    // test mixed-case to mixed-case (expect error)
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "ETH",
        "from": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "to_address_format":{"format":"mixedcase"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        },
    });
    assert_eq!(actual, expected);

    // test invalid address
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "ETH",
        "from": "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "to_address_format":{"format":"mixedcase"},
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!convertaddress success but should be error: {}",
        rc.1
    );
    assert!(rc.1.contains("Address must be prefixed with 0x"));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_add_delegation_qtum() {
    let coins = json!([{
      "coin": "tQTUM",
      "name": "qtumtest",
      "fname": "Qtum test",
      "rpcport": 13889,
      "pubtype": 120,
      "p2shtype": 110,
      "wiftype": 239,
      "txfee": 400000,
      "mm2": 1,
      "required_confirmations": 1,
      "mature_confirmations": 2000,
      "avg_blocktime": 0.53,
      "protocol": {
        "type": "QTUM"
      }
    }]);
    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var("BOB_TRADE_IP").ok(),
            "rpcip": env::var("BOB_TRADE_IP").ok(),
            "canbind": env::var("BOB_TRADE_PORT").ok().map(|s| s.parse::<i64>().unwrap()),
            "passphrase": "asthma turtle lizard tone genuine tube hunt valley soap cloth urge alpha amazing frost faculty cycle mammal leaf normal bright topple avoid pulse buffalo",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
        .unwrap();

    let json = block_on(enable_electrum(
        &mm,
        "tQTUM",
        false,
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        None,
    ));
    println!("{}", json.balance);

    let rc = block_on(mm.rpc(&json!({
        "userpass": "pass",
        "mmrpc": "2.0",
        "method": "add_delegation",
        "params": {
            "coin": "tQTUM",
            "staking_details": {
                "type": "Qtum",
                "address": "qcyBHeSct7Wr4mAw18iuQ1zW5mMFYmtmBE"
            }
        },
        "id": 0
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «add_delegation» failed with status «{}»",
        rc.0
    );
    let rc = block_on(mm.rpc(&json!({
        "userpass": "pass",
        "mmrpc": "2.0",
        "method": "add_delegation",
        "params": {
            "coin": "tQTUM",
            "staking_details": {
                "type": "Qtum",
                "address": "fake_address"
            }
        },
        "id": 0
    })))
    .unwrap();
    assert!(
        rc.0.is_client_error(),
        "!add_delegation success but should be error: {}",
        rc.1
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_remove_delegation_qtum() {
    let coins = json!([{
      "coin": "tQTUM",
      "name": "qtumtest",
      "fname": "Qtum test",
      "rpcport": 13889,
      "pubtype": 120,
      "p2shtype": 110,
      "wiftype": 239,
      "txfee": 400000,
      "mm2": 1,
      "required_confirmations": 1,
      "mature_confirmations": 2000,
      "avg_blocktime": 0.53,
      "protocol": {
        "type": "QTUM"
      }
    }]);
    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var("BOB_TRADE_IP").ok(),
            "rpcip": env::var("BOB_TRADE_IP").ok(),
            "canbind": env::var("BOB_TRADE_PORT").ok().map(|s| s.parse::<i64>().unwrap()),
            "passphrase": "federal stay trigger hour exist success game vapor become comfort action phone bright ill target wild nasty crumble dune close rare fabric hen iron",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
        .unwrap();

    let json = block_on(enable_electrum(
        &mm,
        "tQTUM",
        false,
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        None,
    ));
    println!("{}", json.balance);

    let rc = block_on(mm.rpc(&json!({
        "userpass": "pass",
        "mmrpc": "2.0",
        "method": "remove_delegation",
        "params": {"coin": "tQTUM"},
        "id": 0
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «remove_delegation» failed with status «{}»",
        rc.0
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_staking_infos_qtum() {
    let coins = json!([{
      "coin": "tQTUM",
      "name": "qtumtest",
      "fname": "Qtum test",
      "rpcport": 13889,
      "pubtype": 120,
      "p2shtype": 110,
      "wiftype": 239,
      "txfee": 400000,
      "mm2": 1,
      "required_confirmations": 1,
      "mature_confirmations": 2000,
      "avg_blocktime": 0.53,
      "protocol": {
        "type": "QTUM"
      }
    }]);
    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var("BOB_TRADE_IP").ok(),
            "rpcip": env::var("BOB_TRADE_IP").ok(),
            "canbind": env::var("BOB_TRADE_PORT").ok().map(|s| s.parse::<i64>().unwrap()),
            "passphrase": "federal stay trigger hour exist success game vapor become comfort action phone bright ill target wild nasty crumble dune close rare fabric hen iron",
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
        .unwrap();

    let json = block_on(enable_electrum(
        &mm,
        "tQTUM",
        false,
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        None,
    ));
    println!("{}", json.balance);

    let rc = block_on(mm.rpc(&json!({
        "userpass": "pass",
        "mmrpc": "2.0",
        "method": "get_staking_infos",
        "params": {"coin": "tQTUM"},
        "id": 0
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «get_staking_infos» failed with status «{}»",
        rc.0
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_convert_qrc20_address() {
    let passphrase = "cV463HpebE2djP9ugJry5wZ9st5cc6AbkHXGryZVPXMH1XJK8cVU";
    let coins = json! ([
        {"coin":"QRC20","required_confirmations":0,"pubtype": 120,"p2shtype": 50,"wiftype": 128,"txfee": 0,"mm2": 1,"mature_confirmations":2000,
         "protocol":{"type":"QRC20","protocol_data":{"platform":"QTUM","contract_address":"0xd362e096e873eb7907e205fadc6175c6fec7bc44"}}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm.mm_dump();
    log!("Bob log path: {}", mm.log_path.display());
    let _electrum = block_on(enable_qrc20(
        &mm,
        "QRC20",
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        "0xba8b71f3544b93e2f681f996da519a98ace0107a",
        None,
    ));

    // test wallet to contract
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "QRC20",
        "from": "qKVvtDqpnFGDxsDzck5jmLwdnD2jRH6aM8",
        "to_address_format":{"format":"contract"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "0x1549128bbfb33b997949b4105b6a6371c998e212",
        },
    });
    assert_eq!(actual, expected);

    // test contract to wallet
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "QRC20",
        "from": "0x1549128bbfb33b997949b4105b6a6371c998e212",
        "to_address_format":{"format":"wallet"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "qKVvtDqpnFGDxsDzck5jmLwdnD2jRH6aM8",
        },
    });
    assert_eq!(actual, expected);

    // test wallet to wallet
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "QRC20",
        "from": "qKVvtDqpnFGDxsDzck5jmLwdnD2jRH6aM8",
        "to_address_format":{"format":"wallet"},
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «convertaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "address": "qKVvtDqpnFGDxsDzck5jmLwdnD2jRH6aM8",
        },
    });
    assert_eq!(actual, expected);

    // test invalid address (invalid prefixes)
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "QRC20",
        "from": "RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD",
        "to_address_format":{"format":"contract"},
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!convertaddress success but should be error: {}",
        rc.1
    );
    log!("{}", rc.1);
    assert!(rc.1.contains("invalid address prefix"));

    // test invalid address
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "convertaddress",
        "coin": "QRC20",
        "from": "0000000000000000000000000000000000",
        "to_address_format":{"format":"wallet"},
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "!convertaddress success but should be error: {}",
        rc.1
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_validateaddress() {
    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let (bob_file_passphrase, _bob_file_userpass) = from_env_file(slurp(&".env.seed").unwrap());
    let bob_passphrase = var("BOB_PASSPHRASE")
        .ok()
        .or(bob_file_passphrase)
        .expect("No BOB_PASSPHRASE or .env.seed/BOB_PASSPHRASE");

    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var("BOB_TRADE_IP").ok(),
            "rpcip": env::var("BOB_TRADE_IP").ok(),
            "canbind": env::var("BOB_TRADE_PORT").ok().map(|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    log!("{:?}", block_on(enable_coins_eth_electrum(&mm, ETH_DEV_NODES, None)));

    // test valid RICK address

    let rc = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "validateaddress",
        "coin": "RICK",
        "address": "RRnMcSeKiLrNdbp91qNVQwwXx5azD4S4CD",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "is_valid": true,
        },
    });
    assert_eq!(actual, expected);

    // test valid ETH address

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "validateaddress",
        "coin": "ETH",
        "address": "0x7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "is_valid": true,
        },
    });
    assert_eq!(actual, expected);

    // test invalid RICK address (legacy address format activated)

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "validateaddress",
        "coin": "RICK",
        "address": "bchtest:qr39na5d25wdeecgw3euh9fkd4ygvd4pnsury96597",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );
    let json: Json = json::from_str(&rc.1).unwrap();
    let result = &json["result"];

    assert!(!result["is_valid"].as_bool().unwrap());
    let reason = result["reason"].as_str().unwrap();
    log!("{}", reason);
    assert!(reason.contains("Legacy address format activated for RICK, but CashAddress format used instead"));

    // test invalid RICK address (invalid prefixes)

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "validateaddress",
        "coin": "RICK",
        "address": "1DmFp16U73RrVZtYUbo2Ectt8mAnYScpqM",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );

    let json: Json = json::from_str(&rc.1).unwrap();
    let result = &json["result"];

    assert!(!result["is_valid"].as_bool().unwrap());
    let reason = result["reason"].as_str().unwrap();
    log!("{}", reason);
    assert!(reason.contains("invalid address prefix"));

    // test invalid ETH address

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "validateaddress",
        "coin": "ETH",
        "address": "7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );
    let json: Json = json::from_str(&rc.1).unwrap();
    let result = &json["result"];

    assert!(!result["is_valid"].as_bool().unwrap());
    let reason = result["reason"].as_str().unwrap();
    log!("{}", reason);
    assert!(reason.contains("Address must be prefixed with 0x"));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_validateaddress_segwit() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";

    let coins = json! ([
        {
            "coin": "tBTC",
            "name": "tbitcoin",
            "fname": "tBitcoin",
            "rpcport": 18332,
            "pubtype": 111,
            "p2shtype": 196,
            "wiftype": 239,
            "segwit": true,
            "bech32_hrp": "tb",
            "txfee": 1000,
            "mm2": 1,
            "required_confirmations": 0,
            "protocol": {
                "type": "UTXO"
            },
            "address_format": {
                "format":"segwit"
            }
        }
    ]);

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8100,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": seed.to_string(),
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // wait until RPC API is active

    // Enable coins. Print the replies in case we need the address.
    let electrum = block_on(mm_alice.rpc(&json!({
        "userpass": mm_alice.userpass,
        "method": "electrum",
        "coin": "tBTC",
        "servers": [{"url":"electrum1.cipig.net:10068"},{"url":"electrum2.cipig.net:10068"},{"url":"electrum3.cipig.net:10068"}],
        "mm2": 1,
        "address_format": {
            "format": "segwit",
        },
    }))).unwrap();
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with {} {}",
        electrum.0,
        electrum.1
    );
    log!("enable_coins (alice): {:?}", electrum);

    let electrum_response: CoinInitResponse = json::from_str(&electrum.1).expect("Expected 'CoinInitResponse'");
    let mut enable_res = HashMap::new();
    enable_res.insert("tBTC", electrum_response);

    // test valid Segwit address
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "validateaddress",
        "coin": "tBTC",
        "address": "tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );
    let actual: Json = json::from_str(&rc.1).unwrap();

    let expected = json!({
        "result": {
            "is_valid": true,
        },
    });
    assert_eq!(actual, expected);

    // test invalid tBTC Segwit address (invalid hrp)
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "validateaddress",
        "coin": "tBTC",
        "address": "bc1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5",
    })))
    .unwrap();
    assert_eq!(
        rc.0,
        StatusCode::OK,
        "RPC «validateaddress» failed with status «{}»",
        rc.0
    );

    let json: Json = json::from_str(&rc.1).unwrap();
    let result = &json["result"];

    assert!(!result["is_valid"].as_bool().unwrap());
    let reason = result["reason"].as_str().unwrap();
    log!("{}", reason);
    assert!(reason.contains("Cannot determine format"));

    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn qrc20_activate_electrum() {
    let passphrase = "cV463HpebE2djP9ugJry5wZ9st5cc6AbkHXGryZVPXMH1XJK8cVU";
    let coins = json! ([
        {"coin":"QRC20","required_confirmations":0,"pubtype": 120,"p2shtype": 50,"wiftype": 128,"txfee": 0,"mm2": 1,"mature_confirmations":2000,
         "protocol":{"type":"QRC20","protocol_data":{"platform":"QTUM","contract_address":"0xd362e096e873eb7907e205fadc6175c6fec7bc44"}}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm.mm_dump();
    log!("Bob log path: {}", mm.log_path.display());
    let electrum_json = block_on(enable_qrc20(
        &mm,
        "QRC20",
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        "0xba8b71f3544b93e2f681f996da519a98ace0107a",
        None,
    ));
    assert_eq!(
        electrum_json["address"].as_str(),
        Some("qKEDGuogDhtH9zBnc71QtqT1KDamaR1KJ3")
    );
    assert_eq!(electrum_json["balance"].as_str(), Some("139"));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_qrc20_withdraw() {
    // corresponding private key: [3, 98, 177, 3, 108, 39, 234, 144, 131, 178, 103, 103, 127, 80, 230, 166, 53, 68, 147, 215, 42, 216, 144, 72, 172, 110, 180, 13, 123, 179, 10, 49]
    let passphrase = "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL";
    let coins = json!([
        {"coin":"QRC20","required_confirmations":0,"pubtype": 120,"p2shtype": 50,"wiftype": 128,"txfee": 0,"mm2": 1,"mature_confirmations":2000,
         "protocol":{"type":"QRC20","protocol_data":{"platform":"QTUM","contract_address":"0xd362e096e873eb7907e205fadc6175c6fec7bc44"}}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm.mm_dump();
    log!("Bob log path: {}", mm.log_path.display());

    let electrum_json = block_on(enable_qrc20(
        &mm,
        "QRC20",
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        "0xba8b71f3544b93e2f681f996da519a98ace0107a",
        None,
    ));
    assert_eq!(
        electrum_json["address"].as_str(),
        Some("qXxsj5RtciAby9T7m98AgAATL4zTi4UwDG")
    );
    log!("electrum_json: {:?}", electrum_json);
    let balance: f64 = electrum_json["balance"].as_str().unwrap().parse().unwrap();
    log!("Balance {}", balance);

    let amount = 10;

    let withdraw = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "withdraw",
        "coin": "QRC20",
        "to": "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs",
        "amount": amount,
        "fee": {
            "type": "Qrc20Gas",
            "gas_limit": 2_500_000,
            "gas_price": 40,
        }
    })))
    .unwrap();

    let withdraw_json: Json = json::from_str(&withdraw.1).unwrap();
    assert!(withdraw.0.is_success(), "QRC20 withdraw: {}", withdraw.1);

    log!("{}", withdraw_json);
    assert!(withdraw_json["tx_hex"].as_str().unwrap().contains("5403a02526012844a9059cbb0000000000000000000000000240b898276ad2cc0d2fe6f527e8e31104e7fde3000000000000000000000000000000000000000000000000000000003b9aca0014d362e096e873eb7907e205fadc6175c6fec7bc44c2"));

    let send_tx = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "send_raw_transaction",
        "coin": "QRC20",
        "tx_hex": withdraw_json["tx_hex"],
    })))
    .unwrap();
    assert!(send_tx.0.is_success(), "QRC20 send_raw_transaction: {}", send_tx.1);
    log!("{}", send_tx.1);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_qrc20_withdraw_error() {
    let passphrase = "album hollow help heart use bird response large lounge fat elbow coral";
    let coins = json!([
        {"coin":"QRC20","required_confirmations":0,"pubtype": 120,"p2shtype": 50,"wiftype": 128,"txfee": 0,"mm2": 1,"mature_confirmations":2000,
         "protocol":{"type":"QRC20","protocol_data":{"platform":"QTUM","contract_address":"0xd362e096e873eb7907e205fadc6175c6fec7bc44"}}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    let electrum_json = block_on(enable_qrc20(
        &mm,
        "QRC20",
        &[
            "electrum1.cipig.net:10071",
            "electrum2.cipig.net:10071",
            "electrum3.cipig.net:10071",
        ],
        "0xba8b71f3544b93e2f681f996da519a98ace0107a",
        None,
    ));
    let balance = electrum_json["balance"].as_str().unwrap();
    assert_eq!(balance, "10");

    // try to transfer more than balance
    let withdraw = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "withdraw",
        "coin": "QRC20",
        "to": "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs",
        "amount": "11",
    })))
    .unwrap();
    assert!(
        withdraw.0.is_server_error(),
        "withdraw should have failed, but got {:?}",
        withdraw
    );
    log!("{:?}", withdraw.1);
    assert!(withdraw
        .1
        .contains("Not enough QRC20 to withdraw: available 10, required at least 11"));

    // try to transfer with zero QTUM balance
    let withdraw = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "withdraw",
        "coin": "QRC20",
        "to": "qHmJ3KA6ZAjR9wGjpFASn4gtUSeFAqdZgs",
        "amount": "2",
        "fee": {
            "type": "Qrc20Gas",
            "gas_limit": 100_000,
            "gas_price": 40,
        }
    })))
    .unwrap();
    assert!(
        withdraw.0.is_server_error(),
        "withdraw should have failed, but got {:?}",
        withdraw
    );
    log!("{:?}", withdraw.1);
    // 0.04 = 100_000 * 40 / 100_000_000
    assert!(withdraw
        .1
        .contains("Not enough QTUM to withdraw: available 0, required at least 0.04"));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_raw_transaction() {
    let coins = json! ([
        {"coin":"RICK","asset":"RICK","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"ETH","name":"ethereum","protocol":{"type":"ETH"}},
    ]);
    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "boob",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
            "metrics_interval": 30.,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());
    // RICK
    let _electrum = block_on(enable_electrum(&mm, "RICK", false, DOC_ELECTRUM_ADDRS, None));
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "RICK",
            "tx_hash": "a3ebedbe20f82e43708f276152cf7dfb03a6050921c8f266e48c00ab66e891fb",
        },
        "id": 0,
    })))
    .unwrap();
    assert!(raw.0.is_success(), "get_raw_transaction for coin RICK: {}", raw.1);
    let res: RpcSuccessResponse<RawTransactionResult> =
        json::from_str(&raw.1).expect("Expected 'RpcSuccessResponse<RawTransactionResult>'");
    let expected_hex = "0400008085202f8901e15182af2c252bcfbd58884f3bdbd4d85ed036e53cfe2fd1f904ecfea10cb9f2010000006b483045022100d2435e0c9211114271ac452dc47fd08d3d2dc4bdd484d5750ee6bbda41056d520220408bfb236b7028b6fde0e59a1b6522949131a611584cce36c3df1e934c1748630121022d7424c741213a2b9b49aebdaa10e84419e642a8db0a09e359a3d4c850834846ffffffff02a09ba104000000001976a914054407d1a2224268037cfc7ca3bc438d082bedf488acdd28ce9157ba11001976a914046922483fab8ca76b23e55e9d338605e2dbab6088ac03d63665000000000000000000000000000000";
    assert_eq!(res.result.tx_hex, expected_hex);

    // ETH
    let eth = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "enable",
        "coin": "ETH",
        "urls": &[ETH_MAINNET_NODE],
        // Dev chain swap contract address
        "swap_contract_address": ETH_MAINNET_SWAP_CONTRACT,
        "mm2": 1,
    })))
    .unwrap();
    assert_eq!(eth.0, StatusCode::OK, "'enable' failed: {}", eth.1);
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "ETH",
            // valid hash with 0x prefix
            "tx_hash": "0x02c261dcb1c8615c029b9abc712712b80ef8c1ef20d2cbcdd9bde859e7913476",
        },
        "id": 0,
    })))
    .unwrap();
    assert!(raw.0.is_success(), "get_raw_transaction for coin ETH: {}", raw.1);
    let res: RpcSuccessResponse<RawTransactionResult> =
        json::from_str(&raw.1).expect("Expected 'RpcSuccessResponse<RawTransactionResult>'");
    let expected_hex = "f9012a19851a0de19041830249f09424abe4c71fc658c91313b6552cd40cd808b3ea8080b8c49b415b2a167d3413b0116abb8e99f4c2d4cd39a64df9bc9950006c4ae884527258247dc100000000000000000000000000000000000000000000000006f05b59d3b200000000000000000000000000000d8775f648430679a709e98d2b0cb6250d2887ef0000000000000000000000000112679fc5e6338a52098ab095bee1e9a15bc630ba9528127bcff524677236f3739cef013311f42000000000000000000000000000000000000000000000000000000000000000000000000000000000619626fa25a0b143893550c8d0164278f94d5fa51ba71e3dfefa112e6f53a575bcb494633a07a00cc60b65e44ae5053257b91c1023b637a38d87ffc32c822591275a6283cd6ec5";
    assert_eq!(res.result.tx_hex, expected_hex);
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "ETH",
            // valid hash without 0x prefix
            "tx_hash": "02c261dcb1c8615c029b9abc712712b80ef8c1ef20d2cbcdd9bde859e7913476",
        },
        "id": 0,
    })))
    .unwrap();
    assert!(raw.0.is_success(), "get_raw_transaction for coin ETH: {}", raw.1);
    let res: RpcSuccessResponse<RawTransactionResult> =
        json::from_str(&raw.1).expect("Expected 'RpcSuccessResponse<RawTransactionResult>'");
    let expected_hex = "f9012a19851a0de19041830249f09424abe4c71fc658c91313b6552cd40cd808b3ea8080b8c49b415b2a167d3413b0116abb8e99f4c2d4cd39a64df9bc9950006c4ae884527258247dc100000000000000000000000000000000000000000000000006f05b59d3b200000000000000000000000000000d8775f648430679a709e98d2b0cb6250d2887ef0000000000000000000000000112679fc5e6338a52098ab095bee1e9a15bc630ba9528127bcff524677236f3739cef013311f42000000000000000000000000000000000000000000000000000000000000000000000000000000000619626fa25a0b143893550c8d0164278f94d5fa51ba71e3dfefa112e6f53a575bcb494633a07a00cc60b65e44ae5053257b91c1023b637a38d87ffc32c822591275a6283cd6ec5";
    assert_eq!(res.result.tx_hex, expected_hex);

    // invalid coin
    let zombi_coin = String::from("ZOMBI");
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": zombi_coin,
            "tx_hash": "0xbdef3970c00752b0dc811cd93faadfd75a7a52e6b8e0b608c5519edcad801359",
        },
        "id": 1,
    })))
    .unwrap();
    assert!(
        raw.0.is_client_error(),
        "get_raw_transaction should have failed, but got: {}",
        raw.1
    );
    let error: RpcErrorResponse<raw_transaction_error::InvalidCoin> = json::from_str(&raw.1).unwrap();
    let expected_error = raw_transaction_error::InvalidCoin { coin: zombi_coin };
    assert_eq!(error.error_type, "NoSuchCoin");
    assert_eq!(error.error_data, Some(expected_error));

    // empty hash
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "ETH",
            "tx_hash": "",
        },
        "id": 2,
    })))
    .unwrap();
    assert!(
        raw.0.is_client_error(),
        "get_raw_transaction should have failed, but got: {}",
        raw.1
    );
    let error: RpcErrorResponse<String> = json::from_str(&raw.1).unwrap();
    assert_eq!(error.error_type, "InvalidHashError");
    // invalid hash
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "ETH",
            "tx_hash": "xx",
        },
        "id": 2,
    })))
    .unwrap();
    assert!(
        raw.0.is_client_error(),
        "get_raw_transaction should have failed, but got: {}",
        raw.1
    );
    let error: RpcErrorResponse<String> = json::from_str(&raw.1).unwrap();
    assert_eq!(error.error_type, "InvalidHashError");

    // valid hash but hash not exist
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "ETH",
            "tx_hash": "0xbdef3970c00752b0dc811cd93faadfd75a7a52e6b8e0b608c000000000000000",
        },
        "id": 3,
    })))
    .unwrap();
    assert!(
        raw.0.is_client_error(),
        "get_raw_transaction should have failed, but got: {}",
        raw.1
    );
    let error: RpcErrorResponse<String> = json::from_str(&raw.1).unwrap();
    assert_eq!(error.error_type, "HashNotExist");
    // valid hash but hash not exist without 0x prefix
    let raw = block_on(mm.rpc(&json! ({
        "mmrpc": "2.0",
        "userpass": mm.userpass,
        "method": "get_raw_transaction",
        "params": {
            "coin": "ETH",
            "tx_hash": "bdef3970c00752b0dc811cd93faadfd75a7a52e6b8e0b608c000000000000000",
        },
        "id": 2,
    })))
    .unwrap();
    assert!(
        raw.0.is_client_error(),
        "get_raw_transaction should have failed, but got: {}",
        raw.1
    );
    let error: RpcErrorResponse<String> = json::from_str(&raw.1).unwrap();
    assert_eq!(error.error_type, "HashNotExist");
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_qrc20_tx_history() { block_on(test_qrc20_history_impl(None)); }

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_tx_history_segwit() {
    let passphrase = "also shoot benefit prefer juice shell elder veteran woman mimic image kidney";
    let coins = json!([
        {"coin":"tBTC","name":"tbitcoin","fname":"tBitcoin","rpcport":18332,"pubtype":111,"p2shtype":196,"wiftype":239,"segwit":true,"bech32_hrp":"tb","txfee":0,"estimate_fee_mode":"ECONOMICAL","mm2":1,"required_confirmations":0,"protocol":{"type":"UTXO"},"address_format":{"format":"segwit"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": passphrase,
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
            "metrics_interval": 30.,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    // enable tBTC to see that to/from segwit addresses are displayed correctly in tx_history
    // and that tx_history is retrieved for the segwit address instead of legacy
    let electrum = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": "tBTC",
        "servers": [{"url":"electrum1.cipig.net:10068"},{"url":"electrum2.cipig.net:10068"},{"url":"electrum3.cipig.net:10068"}],
        "mm2": 1,
        "tx_history": true,
        "address_format": {
            "format": "segwit",
        },
    })))
        .unwrap();
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with status «{}», response «{}»",
        electrum.0,
        electrum.1
    );
    let electrum_json: Json = json::from_str(&electrum.1).unwrap();
    assert_eq!(
        electrum_json["address"].as_str(),
        Some("tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5")
    );

    block_on(wait_till_history_has_records(&mm, "tBTC", 13));

    let tx_history = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "my_tx_history",
        "coin": "tBTC",
        "limit": 13,
    })))
    .unwrap();
    assert_eq!(
        tx_history.0,
        StatusCode::OK,
        "RPC «my_tx_history» failed with status «{}», response «{}»",
        tx_history.0,
        tx_history.1
    );
    log!("{:?}", tx_history.1);
    let tx_history_json: Json = json::from_str(&tx_history.1).unwrap();
    let tx_history_result = &tx_history_json["result"];

    let expected = vec![
        // https://live.blockcypher.com/btc-testnet/tx/17505e47435d1522ebf34b48cf60eda5537539c7a13551f4c091c0bc3fd3181e/
        "17505e47435d1522ebf34b48cf60eda5537539c7a13551f4c091c0bc3fd3181e",
        // https://live.blockcypher.com/btc-testnet/tx/f410e82e8c736b92ea6ec59a148533c8a2c4ad50e871a4e85a77e4546f9b2788/
        "f410e82e8c736b92ea6ec59a148533c8a2c4ad50e871a4e85a77e4546f9b2788",
        // https://live.blockcypher.com/btc-testnet/tx/54a288d017fd24a5eb30dee3e70b77119ac450b90e7316d9a2a4fa01642ff880/
        "54a288d017fd24a5eb30dee3e70b77119ac450b90e7316d9a2a4fa01642ff880",
        // https://live.blockcypher.com/btc-testnet/tx/0ff4d93f358185fbc928be4ddec38cd01241224dc7c09ef297518732e40807d3/
        "0ff4d93f358185fbc928be4ddec38cd01241224dc7c09ef297518732e40807d3",
        // https://live.blockcypher.com/btc-testnet/tx/e7a493f0370a36efbd5d8306de32dd6c354412c5ce4c81832648e7f9b91c1d27/
        "e7a493f0370a36efbd5d8306de32dd6c354412c5ce4c81832648e7f9b91c1d27",
        // https://live.blockcypher.com/btc-testnet/tx/ba9188ba9cd1ff8abb5af7bc6247b88c6f4cd065f93b8fb196de6a39b6ef178c/
        "ba9188ba9cd1ff8abb5af7bc6247b88c6f4cd065f93b8fb196de6a39b6ef178c",
        // https://live.blockcypher.com/btc-testnet/tx/0089a6efa24ace36f0b21956e7a63d8d3185c3cf1b248564b3c6fe0b81e40878/
        "0089a6efa24ace36f0b21956e7a63d8d3185c3cf1b248564b3c6fe0b81e40878",
        // https://live.blockcypher.com/btc-testnet/tx/7f888369d0dedd07ea780bb4bc4795554dd80c62de613381630ae7f49370100f/
        "7f888369d0dedd07ea780bb4bc4795554dd80c62de613381630ae7f49370100f",
        // https://live.blockcypher.com/btc-testnet/tx/369e59d3036abf1b5b519181d762e7776bcecd96a2f0ba3615edde20c928f8e4/
        "369e59d3036abf1b5b519181d762e7776bcecd96a2f0ba3615edde20c928f8e4",
        // https://live.blockcypher.com/btc-testnet/tx/ac4eeb9bc9b776e287b0e15314595d33df8528924b60fb9d4ab57159d5911b9e/
        "ac4eeb9bc9b776e287b0e15314595d33df8528924b60fb9d4ab57159d5911b9e",
        // https://live.blockcypher.com/btc-testnet/tx/16bb7653c5bdb359dbe207aad5fd784e8871e777257b2bbd9349c68f10819e6c/
        "16bb7653c5bdb359dbe207aad5fd784e8871e777257b2bbd9349c68f10819e6c",
        // https://live.blockcypher.com/btc-testnet/tx/8fe0b51bf5c26ebe45fda29bcf24982423445807097df6ee53726551596dfed4/
        "8fe0b51bf5c26ebe45fda29bcf24982423445807097df6ee53726551596dfed4",
        // https://live.blockcypher.com/btc-testnet/tx/3f7421fe2249870083fcc8b1730393542dcb591f36e2a6c9fd3a79388d53264f/
        "3f7421fe2249870083fcc8b1730393542dcb591f36e2a6c9fd3a79388d53264f",
    ];

    for tx in tx_history_result["transactions"].as_array().unwrap() {
        assert!(
            expected.contains(&tx["tx_hash"].as_str().unwrap()),
            "Transaction history must contain expected transactions"
        );
        // https://live.blockcypher.com/btc-testnet/tx/17505e47435d1522ebf34b48cf60eda5537539c7a13551f4c091c0bc3fd3181e/
        if tx["tx_hash"].as_str().unwrap() == "17505e47435d1522ebf34b48cf60eda5537539c7a13551f4c091c0bc3fd3181e" {
            // assert that segwit from address displays correctly
            assert_eq!(
                tx["from"][0].as_str().unwrap(),
                "tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5"
            );
            // assert that legacy P2SH to address displays correctly
            assert_eq!(tx["to"][0].as_str().unwrap(), "2Mw6MLbfd5xrk1Wq785XuGWrpNvEGhHiNU1");
            // assert that segwit to address displays correctly
            assert_eq!(
                tx["to"][1].as_str().unwrap(),
                "tb1qdkwjk42dw6pryvs9sl0ht3pn3mxghuma64jst5"
            );
        }
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_tx_history_tbtc_non_segwit() {
    let passphrase = "also shoot benefit prefer juice shell elder veteran woman mimic image kidney";
    let coins = json!([
        {"coin":"tBTC","name":"tbitcoin","fname":"tBitcoin","rpcport":18332,"pubtype":111,"p2shtype":196,"wiftype":239,"segwit":true,"bech32_hrp":"tb","txfee":0,"estimate_fee_mode":"ECONOMICAL","mm2":1,"required_confirmations":0,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": passphrase,
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
            "metrics_interval": 30.,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    // enable tBTC in legacy first to see that to/from segwit addresses are displayed correctly in tx_history
    let electrum = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "electrum",
        "coin": "tBTC",
        "servers": [{"url":"electrum1.cipig.net:10068"},{"url":"electrum2.cipig.net:10068"},{"url":"electrum3.cipig.net:10068"}],
        "mm2": 1,
        "tx_history": true,
    })))
        .unwrap();
    assert_eq!(
        electrum.0,
        StatusCode::OK,
        "RPC «electrum» failed with status «{}», response «{}»",
        electrum.0,
        electrum.1
    );
    let electrum_json: Json = json::from_str(&electrum.1).unwrap();
    assert_eq!(
        electrum_json["address"].as_str(),
        Some("mqWYEGxLeK843n3xMTe8EWTFPyoSZjtUXb")
    );

    let expected = vec![
        // https://live.blockcypher.com/btc-testnet/tx/a41b2e5f0741d1dcbc309ce4c43fde1ad44c5e61bb34778ab0bf9f3d9fd6fb6c/
        "a41b2e5f0741d1dcbc309ce4c43fde1ad44c5e61bb34778ab0bf9f3d9fd6fb6c",
        // https://live.blockcypher.com/btc-testnet/tx/9c1ca9de9f3a47d71c8113209123410f44048c67951bf49cdfb1a84c2cc6a55b/
        "9c1ca9de9f3a47d71c8113209123410f44048c67951bf49cdfb1a84c2cc6a55b",
        // https://live.blockcypher.com/btc-testnet/tx/ac6218b33d02e069c4055af709bbb6ca92ce11e55450cde96bc17411e281e5e7/
        "ac6218b33d02e069c4055af709bbb6ca92ce11e55450cde96bc17411e281e5e7",
        // https://live.blockcypher.com/btc-testnet/tx/7276c67f996fb0b5ef653bb4c3601541407cc785238dcc50c308eb29291a0f44/
        "7276c67f996fb0b5ef653bb4c3601541407cc785238dcc50c308eb29291a0f44",
        // https://live.blockcypher.com/btc-testnet/tx/17829d32cd096092b239db5d488e587c1bccbbc9075f1adbf2887a49ee0f5953/
        "17829d32cd096092b239db5d488e587c1bccbbc9075f1adbf2887a49ee0f5953",
        // https://live.blockcypher.com/btc-testnet/tx/45dc84d7ac675a2d9c98542b0147ea27d409e0555dcb50781de8dd633b5365ba/
        "45dc84d7ac675a2d9c98542b0147ea27d409e0555dcb50781de8dd633b5365ba",
        // https://live.blockcypher.com/btc-testnet/tx/2c53d71c0262d939bde0da5cad5231cef1194587f58550e20bb1630d6a8c2298/
        "2c53d71c0262d939bde0da5cad5231cef1194587f58550e20bb1630d6a8c2298",
        // https://live.blockcypher.com/btc-testnet/tx/4493f6a5238c02cf3075e1434bf89a07ef2f3309f75b54ddc9597907c8137857/
        "4493f6a5238c02cf3075e1434bf89a07ef2f3309f75b54ddc9597907c8137857",
        // https://live.blockcypher.com/btc-testnet/tx/0cfbc82975d9b6ddb467e51acfeff4a488d96550cea2bdffa4559ba1d72f9cfb/
        "0cfbc82975d9b6ddb467e51acfeff4a488d96550cea2bdffa4559ba1d72f9cfb",
        // https://live.blockcypher.com/btc-testnet/tx/1931ab544817b417a2a655cd779520feb3a3dac525e2c1fbf0296282ad1ed265/
        "1931ab544817b417a2a655cd779520feb3a3dac525e2c1fbf0296282ad1ed265",
        // https://live.blockcypher.com/btc-testnet/tx/245f0a072bed336be95cb2b5a7fb080cc4b57b95e1db7c3c4152d58705e3a72e/
        "245f0a072bed336be95cb2b5a7fb080cc4b57b95e1db7c3c4152d58705e3a72e",
        // https://live.blockcypher.com/btc-testnet/tx/8f401f6ea5607a7772e77ff18d97d769433a1baddffa0a84234e0555599d5b5c/
        "8f401f6ea5607a7772e77ff18d97d769433a1baddffa0a84234e0555599d5b5c",
        // https://live.blockcypher.com/btc-testnet/tx/15e3b61a5025cac9bfcbd9d6cc9fefc01671e5e7442d1b73de6c6024c2be2c96/
        "15e3b61a5025cac9bfcbd9d6cc9fefc01671e5e7442d1b73de6c6024c2be2c96",
        // https://live.blockcypher.com/btc-testnet/tx/ec2a6c46283860f9d2dc76ac4c9d6f216ed3a897a9bdac5caa7d6fcd24d43ca9/
        "ec2a6c46283860f9d2dc76ac4c9d6f216ed3a897a9bdac5caa7d6fcd24d43ca9",
        // https://live.blockcypher.com/btc-testnet/tx/322d46e09d3668dc5b04baa83bf31fc88530a205f70f5500a8d4f7ab73e45d37/
        "322d46e09d3668dc5b04baa83bf31fc88530a205f70f5500a8d4f7ab73e45d37",
        // https://live.blockcypher.com/btc-testnet/tx/db2c760eb14328e5b237b982685f9366ccaa54e6d6a7b19f733d9ccf50e5cb69/
        "db2c760eb14328e5b237b982685f9366ccaa54e6d6a7b19f733d9ccf50e5cb69",
        // https://live.blockcypher.com/btc-testnet/tx/4fad7ebdbc7c6f3a59638af1a559fbde93d7235e2f382d84581640ea32887f6a/
        "4fad7ebdbc7c6f3a59638af1a559fbde93d7235e2f382d84581640ea32887f6a",
        // https://live.blockcypher.com/btc-testnet/tx/a9b15d2e9ec3dc6341c69e412b7daf5f971227eb23a77f29e808b327679a07c1/
        "a9b15d2e9ec3dc6341c69e412b7daf5f971227eb23a77f29e808b327679a07c1",
        // https://live.blockcypher.com/btc-testnet/tx/2f731488360d85fdab70c9d819647661726c2b9c833abda907cf72fdfc846e35/
        "2f731488360d85fdab70c9d819647661726c2b9c833abda907cf72fdfc846e35",
        // https://live.blockcypher.com/btc-testnet/tx/6d4d0a844dcbd3f839f071b101dc69d01ee902ad18d2f44531bdeffb0e381c60/
        "6d4d0a844dcbd3f839f071b101dc69d01ee902ad18d2f44531bdeffb0e381c60",
        // https://live.blockcypher.com/btc-testnet/tx/303d1797bd67895dab9289e6729886518d6e1ef34f15e49fbaaa3204db832b7f/
        "303d1797bd67895dab9289e6729886518d6e1ef34f15e49fbaaa3204db832b7f",
        // https://live.blockcypher.com/btc-testnet/tx/adaaf2d775dbee268d3ce2a02c389525c7d4b1034313bd00d207691e7dde42e0/
        "adaaf2d775dbee268d3ce2a02c389525c7d4b1034313bd00d207691e7dde42e0",
        // https://live.blockcypher.com/btc-testnet/tx/649d514d76702a0925a917d830e407f4f1b52d78832520e486c140ce8d0b879f/
        "649d514d76702a0925a917d830e407f4f1b52d78832520e486c140ce8d0b879f",
    ];

    block_on(wait_till_history_has_records(&mm, "tBTC", expected.len()));

    let tx_history = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "method": "my_tx_history",
        "coin": "tBTC",
        "limit": 100,
    })))
    .unwrap();
    assert_eq!(
        tx_history.0,
        StatusCode::OK,
        "RPC «my_tx_history» failed with status «{}», response «{}»",
        tx_history.0,
        tx_history.1
    );
    log!("{:?}", tx_history.1);
    let tx_history_json: Json = json::from_str(&tx_history.1).unwrap();
    let tx_history_result = &tx_history_json["result"];

    assert_eq!(tx_history_result["total"].as_u64().unwrap(), expected.len() as u64);
    for tx in tx_history_result["transactions"].as_array().unwrap() {
        // https://live.blockcypher.com/btc-testnet/tx/6d4d0a844dcbd3f839f071b101dc69d01ee902ad18d2f44531bdeffb0e381c60/
        if tx["tx_hash"].as_str().unwrap() == "6d4d0a844dcbd3f839f071b101dc69d01ee902ad18d2f44531bdeffb0e381c60" {
            // assert that segwit from address displays correctly
            assert_eq!(
                tx["from"][0].as_str().unwrap(),
                "tb1qqk4t2dppvmu9jja0z7nan0h464n5gve8v3dtus"
            );
            // assert that legacy to address displays correctly
            assert_eq!(tx["to"][0].as_str().unwrap(), "mqWYEGxLeK843n3xMTe8EWTFPyoSZjtUXb");
            // assert that segwit to address displays correctly
            assert_eq!(
                tx["to"][1].as_str().unwrap(),
                "tb1qqk4t2dppvmu9jja0z7nan0h464n5gve8v3dtus"
            );
        }
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_buy_conf_settings() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(),
    {"coin":"JST","name":"jst","protocol":{"type":"ERC20","protocol_data":{"platform":"ETH","contract_address":ETH_DEV_TOKEN_CONTRACT}},"required_confirmations":2},]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob buy request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);
    let json: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(json["result"]["conf_settings"]["base_confs"], Json::from(5));
    assert_eq!(json["result"]["conf_settings"]["base_nota"], Json::from(true));
    assert_eq!(json["result"]["conf_settings"]["rel_confs"], Json::from(4));
    assert_eq!(json["result"]["conf_settings"]["rel_nota"], Json::from(false));

    // must use coin config as defaults if not set in request
    log!("Issue bob buy request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);
    let json: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(json["result"]["conf_settings"]["base_confs"], Json::from(1));
    assert_eq!(json["result"]["conf_settings"]["base_nota"], Json::from(false));
    assert_eq!(json["result"]["conf_settings"]["rel_confs"], Json::from(2));
    assert_eq!(json["result"]["conf_settings"]["rel_nota"], Json::from(false));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_buy_response_format() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob buy request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);
    let _: BuyOrSellRpcResult = json::from_str(&rc.1).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sell_response_format() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let _: BuyOrSellRpcResult = json::from_str(&rc.1).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_my_orders_response_format() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob buy request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);

    log!("Issue bob setprice request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    log!("Issue bob my_orders request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);

    let _: MyOrdersRpcResult = json::from_str(&rc.1).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_my_orders_after_matched() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();
    let alice_passphrase = get_passphrase(&".env.client", "ALICE_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": alice_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "seednodes": vec![format!("{}", mm_bob.ip)],
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();

    // Enable coins on Bob side. Print the replies in case we need the address.
    let rc = block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None));
    log!("enable_coins (bob): {:?}", rc);
    // Enable coins on Alice side. Print the replies in case we need the address.
    let rc = block_on(enable_coins_eth_electrum(&mm_alice, ETH_DEV_NODES, None));
    log!("enable_coins (alice): {:?}", rc);

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.000001,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.000001,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);

    block_on(mm_bob.wait_for_log(22., |log| log.contains("Entering the maker_swap_loop ETH/JST"))).unwrap();
    block_on(mm_alice.wait_for_log(22., |log| log.contains("Entering the taker_swap_loop ETH/JST"))).unwrap();

    log!("Issue bob my_orders request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);

    let _: MyOrdersRpcResult = json::from_str(&rc.1).unwrap();
    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sell_conf_settings() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(),
    {"coin":"JST","name":"jst","protocol":{"type":"ERC20","protocol_data":{"platform":"ETH","contract_address": ETH_DEV_TOKEN_CONTRACT}},"required_confirmations":2},]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let json: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(json["result"]["conf_settings"]["base_confs"], Json::from(5));
    assert_eq!(json["result"]["conf_settings"]["base_nota"], Json::from(true));
    assert_eq!(json["result"]["conf_settings"]["rel_confs"], Json::from(4));
    assert_eq!(json["result"]["conf_settings"]["rel_nota"], Json::from(false));

    // must use coin config as defaults if not set in request
    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let json: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(json["result"]["conf_settings"]["base_confs"], Json::from(1));
    assert_eq!(json["result"]["conf_settings"]["base_nota"], Json::from(false));
    assert_eq!(json["result"]["conf_settings"]["rel_confs"], Json::from(2));
    assert_eq!(json["result"]["conf_settings"]["rel_nota"], Json::from(false));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_set_price_conf_settings() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(),
    {"coin":"JST","name":"jst","protocol":{"type":"ERC20","protocol_data":{"platform":"ETH","contract_address": ETH_DEV_TOKEN_CONTRACT}},"required_confirmations":2},]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let json: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(json["result"]["conf_settings"]["base_confs"], Json::from(5));
    assert_eq!(json["result"]["conf_settings"]["base_nota"], Json::from(true));
    assert_eq!(json["result"]["conf_settings"]["rel_confs"], Json::from(4));
    assert_eq!(json["result"]["conf_settings"]["rel_nota"], Json::from(false));

    // must use coin config as defaults if not set in request
    log!("Issue bob sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.1,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let json: Json = json::from_str(&rc.1).unwrap();
    assert_eq!(json["result"]["conf_settings"]["base_confs"], Json::from(1));
    assert_eq!(json["result"]["conf_settings"]["base_nota"], Json::from(false));
    assert_eq!(json["result"]["conf_settings"]["rel_confs"], Json::from(2));
    assert_eq!(json["result"]["conf_settings"]["rel_nota"], Json::from(false));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_update_maker_order() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json! ([
        {"coin":"RICK","asset":"RICK","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!("{:?}", block_on(enable_coins_rick_morty_electrum(&mm_bob)));

    log!("Issue bob sell request");
    let setprice = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 1,
        "volume": 2,
        "min_volume": 1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(setprice.0.is_success(), "!setprice: {}", setprice.1);
    let setprice_json: Json = json::from_str(&setprice.1).unwrap();
    let uuid: Uuid = json::from_value(setprice_json["result"]["uuid"].clone()).unwrap();

    log!("Issue bob update maker order request");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "new_price": 2,
    })))
    .unwrap();
    assert!(
        update_maker_order.0.is_success(),
        "!update_maker_order: {}",
        update_maker_order.1
    );
    let update_maker_order_json: Json = json::from_str(&update_maker_order.1).unwrap();
    assert_eq!(update_maker_order_json["result"]["price"], Json::from("2"));
    assert_eq!(update_maker_order_json["result"]["max_base_vol"], Json::from("2"));
    assert_eq!(update_maker_order_json["result"]["min_base_vol"], Json::from("1"));

    log!("Issue another bob update maker order request");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "volume_delta": 2,
    })))
    .unwrap();
    assert!(
        update_maker_order.0.is_success(),
        "!update_maker_order: {}",
        update_maker_order.1
    );
    let update_maker_order_json: Json = json::from_str(&update_maker_order.1).unwrap();
    assert_eq!(update_maker_order_json["result"]["price"], Json::from("2"));
    assert_eq!(update_maker_order_json["result"]["max_base_vol"], Json::from("4"));
    assert_eq!(update_maker_order_json["result"]["min_base_vol"], Json::from("1"));

    log!("Get bob balance");
    let my_balance = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_balance",
        "coin": "RICK",
    })))
    .unwrap();
    assert!(my_balance.0.is_success(), "!my_balance: {}", my_balance.1);
    let my_balance_json: Json = json::from_str(&my_balance.1).unwrap();
    let balance: BigDecimal = json::from_value(my_balance_json["balance"].clone()).unwrap();

    log!("Get RICK trade fee");
    let trade_preimage = block_on(mm_bob.rpc(&json!({
        "userpass": mm_bob.userpass,
        "mmrpc": "2.0",
        "method": "trade_preimage",
        "params": {
            "base": "RICK",
            "rel": "MORTY",
            "swap_method": "setprice",
            "price": 2,
            "max": true,
        },
    })))
    .unwrap();
    assert!(trade_preimage.0.is_success(), "!trade_preimage: {}", trade_preimage.1);
    let get_trade_fee_json: Json = json::from_str(&trade_preimage.1).unwrap();
    let trade_fee: BigDecimal =
        json::from_value(get_trade_fee_json["result"]["base_coin_fee"]["amount"].clone()).unwrap();
    let max_volume = balance - trade_fee;

    log!("Issue another bob update maker order request");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "max": true,
    })))
    .unwrap();
    assert!(
        update_maker_order.0.is_success(),
        "!update_maker_order: {}",
        update_maker_order.1
    );
    let update_maker_order_json: Json = json::from_str(&update_maker_order.1).unwrap();
    let max_base_vol =
        BigDecimal::from_str(update_maker_order_json["result"]["max_base_vol"].as_str().unwrap()).unwrap();
    assert_eq!(update_maker_order_json["result"]["price"], Json::from("2"));
    assert_eq!(max_base_vol, max_volume);

    block_on(mm_bob.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_update_maker_order_fail() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json! ([
        {"coin":"RICK","asset":"RICK","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!("{:?}", block_on(enable_coins_rick_morty_electrum(&mm_bob)));

    log!("Issue bob sell request");
    let setprice = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 1,
        "volume": 0.1,
        "base_confs": 5,
        "base_nota": true,
        "rel_confs": 4,
        "rel_nota": false,
    })))
    .unwrap();
    assert!(setprice.0.is_success(), "!setprice: {}", setprice.1);
    let setprice_json: Json = json::from_str(&setprice.1).unwrap();
    let uuid: Uuid = json::from_value(setprice_json["result"]["uuid"].clone()).unwrap();

    log!("Issue bob update maker order request that should fail because price is too low");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "new_price": 0.0000000099,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue bob update maker order request that should fail because New Volume is Less than Zero");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "volume_delta": -0.11,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue bob update maker order request that should fail because Min base vol is too low");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "new_price": 2,
        "min_volume": 0.000099,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue bob update maker order request that should fail because Max base vol is below Min base vol");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "volume_delta": -0.0999,
        "min_volume": 0.0002,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue bob update maker order request that should fail because Max base vol is too low");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "new_price": 2,
        "volume_delta": -0.099901,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue bob update maker order request that should fail because Max rel vol is too low");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "new_price": 0.5,
        "volume_delta": -0.099802,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue bob batch of 2 update maker order requests that should make the second request fail because the order state changed due to the first request");
    let batch_json = json!([
        {
            "userpass": mm_bob.userpass,
            "method": "update_maker_order",
            "uuid": uuid,
            "new_price": 3,
            "volume_delta": 1,
        },
        {
            "userpass": mm_bob.userpass,
            "method": "update_maker_order",
            "uuid": uuid,
            "new_price": 2,
            "volume_delta": 1,
        },
    ]);

    let rc = block_on(mm_bob.rpc(&batch_json)).unwrap();
    assert!(rc.0.is_success(), "!batch: {}", rc.1);
    log!("{}", rc.1);
    let err_msg = "Order state has changed after price/volume/balance checks. Please try to update the order again if it's still needed.";
    let responses = json::from_str::<Vec<Json>>(&rc.1).unwrap();
    if responses[0].get("error").is_some() {
        assert!(responses[0]["error"].as_str().unwrap().contains(err_msg));
        assert!(responses[1].get("result").is_some());
    } else if responses[1].get("error").is_some() {
        assert!(responses[0].get("result").is_some());
        assert!(responses[1]["error"].as_str().unwrap().contains(err_msg));
    }

    log!("Issue bob batch update maker order and cancel order request that should make update maker order fail because Order with UUID has been deleted");
    let batch_json = json!([
        {
            "userpass": mm_bob.userpass,
            "method": "update_maker_order",
            "uuid": uuid,
            "new_price": 1,
            "volume_delta": 2.9,
        },
        {
            "userpass": mm_bob.userpass,
            "method": "cancel_order",
            "uuid": uuid,
        },
    ]);

    let rc = block_on(mm_bob.rpc(&batch_json)).unwrap();
    assert!(rc.0.is_success(), "!batch: {}", rc.1);
    log!("{}", rc.1);
    let err_msg = format!("Order with UUID: {} has been deleted", uuid);
    let responses = json::from_str::<Vec<Json>>(&rc.1).unwrap();
    if responses[0].get("error").is_some() {
        assert!(responses[0]["error"].as_str().unwrap().contains(&err_msg));
        assert!(responses[1].get("result").is_some());
    } else if responses[1].get("error").is_some() {
        assert!(responses[0].get("result").is_some());
        assert!(responses[1]["error"].as_str().unwrap().contains(&err_msg));
    }

    block_on(mm_bob.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_update_maker_order_after_matched() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();
    let alice_passphrase = get_passphrase(&".env.client", "ALICE_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": alice_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "seednodes": vec![format!("{}", mm_bob.ip)],
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();

    // Enable coins on Bob side. Print the replies in case we need the address.
    let rc = block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None));
    log!("enable_coins (bob): {:?}", rc);
    // Enable coins on Alice side. Print the replies in case we need the address.
    let rc = block_on(enable_coins_eth_electrum(&mm_alice, ETH_DEV_NODES, None));
    log!("enable_coins (alice): {:?}", rc);

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.00002,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let setprice_json: Json = json::from_str(&rc.1).unwrap();
    let uuid: Uuid = json::from_value(setprice_json["result"]["uuid"].clone()).unwrap();

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": 1,
        "volume": 0.00001,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);

    block_on(mm_bob.wait_for_log(22., |log| log.contains("Entering the maker_swap_loop ETH/JST"))).unwrap();
    block_on(mm_alice.wait_for_log(22., |log| log.contains("Entering the taker_swap_loop ETH/JST"))).unwrap();

    log!("Issue bob update maker order request that should fail because new volume is less than reserved amount");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "volume_delta": -0.00002,
    })))
    .unwrap();
    assert!(
        !update_maker_order.0.is_success(),
        "update_maker_order success, but should be error {}",
        update_maker_order.1
    );

    log!("Issue another bob update maker order request");
    let update_maker_order = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "update_maker_order",
        "uuid": uuid,
        "volume_delta": 0.00001,
    })))
    .unwrap();
    assert!(
        update_maker_order.0.is_success(),
        "!update_maker_order: {}",
        update_maker_order.1
    );
    let update_maker_order_json: Json = json::from_str(&update_maker_order.1).unwrap();
    log!("{}", update_maker_order.1);
    assert_eq!(update_maker_order_json["result"]["max_base_vol"], Json::from("0.00003"));

    log!("Issue bob my_orders request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);

    let _: MyOrdersRpcResult = json::from_str(&rc.1).unwrap();
    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

// https://github.com/KomodoPlatform/atomicDEX-API/issues/683
// trade fee should return numbers in all 3 available formats and
// "amount" must be always in decimal representation for backwards compatibility
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_trade_fee_returns_numbers_in_various_formats() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    block_on(enable_coins_rick_morty_electrum(&mm_bob));

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "get_trade_fee",
        "coin": "RICK",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!get_trade_fee: {}", rc.1);
    let trade_fee_json: Json = json::from_str(&rc.1).unwrap();
    let _amount_dec: BigDecimal = json::from_value(trade_fee_json["result"]["amount"].clone()).unwrap();
    let _amount_rat: BigRational = json::from_value(trade_fee_json["result"]["amount_rat"].clone()).unwrap();
    let _amount_fraction: Fraction = json::from_value(trade_fee_json["result"]["amount_fraction"].clone()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_orderbook_is_mine_orders() {
    let coins = json!([{"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": "bob passphrase",
            "coins": coins,
            "i_am_seed": true,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let _bob_setprice: Json = json::from_str(&rc.1).unwrap();

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    // Enable coins on Alice side. Print the replies in case we need the "address".
    log!(
        "enable_coins (alice): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_alice))
    );

    // Bob orderbook must show 1 mine order
    log!("Get RICK/MORTY orderbook on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let bob_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Bob orderbook {:?}", bob_orderbook);
    let asks = bob_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Bob RICK/MORTY orderbook must have exactly 1 ask");
    let is_mine = asks[0]["is_mine"].as_bool().unwrap();
    assert!(is_mine);

    // Alice orderbook must show 1 not-mine order
    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    assert_eq!(asks.len(), 1, "Alice RICK/MORTY orderbook must have exactly 1 ask");
    let is_mine = asks[0]["is_mine"].as_bool().unwrap();
    assert!(!is_mine);

    // make another order by Alice
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 1,
        "volume": 0.1,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);

    log!("Give Bob 2 seconds to import the order…");
    thread::sleep(Duration::from_secs(2));

    // Bob orderbook must show 1 mine and 1 non-mine orders.
    // Request orderbook with reverse base and rel coins to check bids instead of asks
    log!("Get RICK/MORTY orderbook on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "MORTY",
        "rel": "RICK",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let bob_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Bob orderbook {:?}", bob_orderbook);
    let asks = bob_orderbook["asks"].as_array().unwrap();
    let bids = bob_orderbook["bids"].as_array().unwrap();
    assert!(asks.is_empty(), "Bob MORTY/RICK orderbook must contain an empty asks");
    assert_eq!(bids.len(), 2, "Bob MORTY/RICK orderbook must have exactly 2 bids");
    let mine_orders = bids.iter().filter(|bid| bid["is_mine"].as_bool().unwrap()).count();
    assert_eq!(mine_orders, 1, "Bob RICK/MORTY orderbook must have exactly 1 mine bid");

    // Alice orderbook must show 1 mine and 1 non-mine orders
    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: Json = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    let asks = alice_orderbook["asks"].as_array().unwrap();
    let bids = alice_orderbook["bids"].as_array().unwrap();
    assert!(bids.is_empty(), "Alice MORTY/RICK orderbook must contain an empty bids");
    assert_eq!(asks.len(), 2, "Alice MORTY/RICK orderbook must have exactly 2 asks");
    let mine_orders = asks.iter().filter(|ask| ask["is_mine"].as_bool().unwrap()).count();
    assert_eq!(
        mine_orders, 1,
        "Alice RICK/MORTY orderbook must have exactly 1 mine bid"
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sell_min_volume() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    let min_volume: BigDecimal = "0.1".parse().unwrap();
    log!("Issue bob ETH/JST sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "ETH",
        "rel": "JST",
        "price": "1",
        "volume": "1",
        "min_volume": min_volume,
        "order_type": {
            "type": "GoodTillCancelled"
        },
        "timeout": 2,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let rc_json: Json = json::from_str(&rc.1).unwrap();
    let uuid: Uuid = json::from_value(rc_json["result"]["uuid"].clone()).unwrap();
    let min_volume_response: BigDecimal = json::from_value(rc_json["result"]["min_volume"].clone()).unwrap();
    assert_eq!(min_volume, min_volume_response);

    log!("Wait for 4 seconds for Bob order to be converted to maker");
    thread::sleep(Duration::from_secs(4));

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
    let my_orders: Json = json::from_str(&rc.1).unwrap();
    let my_maker_orders: HashMap<Uuid, Json> = json::from_value(my_orders["result"]["maker_orders"].clone()).unwrap();
    let my_taker_orders: HashMap<Uuid, Json> = json::from_value(my_orders["result"]["taker_orders"].clone()).unwrap();
    assert_eq!(1, my_maker_orders.len(), "maker_orders must have exactly 1 order");
    assert!(my_taker_orders.is_empty(), "taker_orders must be empty");
    let maker_order = my_maker_orders.get(&uuid).unwrap();
    let min_volume_maker: BigDecimal = json::from_value(maker_order["min_base_vol"].clone()).unwrap();
    assert_eq!(min_volume, min_volume_maker);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sell_min_volume_dust() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json! ([
        {"coin":"RICK","asset":"RICK","dust":10000000,"required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!("{:?}", block_on(enable_coins_rick_morty_electrum(&mm_bob)));

    log!("Issue bob RICK/MORTY sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "sell",
        "base": "RICK",
        "rel": "MORTY",
        "price": "1",
        "volume": "1",
        "order_type": {
            "type": "FillOrKill"
        }
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let response: BuyOrSellRpcResult = json::from_str(&rc.1).unwrap();
    let expected_min = BigDecimal::from(1);
    assert_eq!(response.result.min_volume, expected_min);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_setprice_min_volume_dust() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json! ([
        {"coin":"RICK","asset":"RICK","dust":10000000,"required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","required_confirmations":0,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!("{:?}", block_on(enable_coins_rick_morty_electrum(&mm_bob)));

    log!("Issue bob RICK/MORTY sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": "1",
        "volume": "1",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let response: SetPriceResponse = json::from_str(&rc.1).unwrap();
    let expected_min = BigDecimal::from(1);
    assert_eq!(expected_min, response.result.min_base_vol);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_buy_min_volume() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    thread::sleep(Duration::from_secs(2));

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    log!(
        "{:?}",
        block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None))
    );

    let min_volume: BigDecimal = "0.1".parse().unwrap();
    log!("Issue bob ETH/JST sell request");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "buy",
        "base": "ETH",
        "rel": "JST",
        "price": "2",
        "volume": "1",
        "min_volume": min_volume,
        "order_type": {
            "type": "GoodTillCancelled"
        },
        "timeout": 2,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!sell: {}", rc.1);
    let response: BuyOrSellRpcResult = json::from_str(&rc.1).unwrap();
    assert_eq!(min_volume, response.result.min_volume);

    log!("Wait for 4 seconds for Bob order to be converted to maker");
    thread::sleep(Duration::from_secs(4));

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
    let my_orders: MyOrdersRpcResult = json::from_str(&rc.1).unwrap();
    assert_eq!(
        1,
        my_orders.result.maker_orders.len(),
        "maker_orders must have exactly 1 order"
    );
    assert!(my_orders.result.taker_orders.is_empty(), "taker_orders must be empty");
    let maker_order = my_orders.result.maker_orders.get(&response.result.uuid).unwrap();

    let expected_min_volume: BigDecimal = "0.2".parse().unwrap();
    assert_eq!(expected_min_volume, maker_order.min_base_vol);
}

#[cfg(not(target_arch = "wasm32"))]
fn request_and_check_orderbook_depth(mm_alice: &MarketMakerIt) {
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook_depth",
        "pairs": [("RICK", "MORTY"), ("RICK", "ETH"), ("MORTY", "ETH")],
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook_depth: {}", rc.1);
    let response: OrderbookDepthResponse = json::from_str(&rc.1).unwrap();
    let rick_morty = response
        .result
        .iter()
        .find(|pair_depth| pair_depth.pair.0 == "RICK" && pair_depth.pair.1 == "MORTY")
        .unwrap();
    assert_eq!(3, rick_morty.depth.asks);
    assert_eq!(2, rick_morty.depth.bids);

    let rick_eth = response
        .result
        .iter()
        .find(|pair_depth| pair_depth.pair.0 == "RICK" && pair_depth.pair.1 == "ETH")
        .unwrap();
    assert_eq!(1, rick_eth.depth.asks);
    assert_eq!(1, rick_eth.depth.bids);

    let morty_eth = response
        .result
        .iter()
        .find(|pair_depth| pair_depth.pair.0 == "MORTY" && pair_depth.pair.1 == "ETH")
        .unwrap();
    assert_eq!(0, morty_eth.depth.asks);
    assert_eq!(0, morty_eth.depth.bids);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_orderbook_depth() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    // start bob and immediately place the orders
    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    // Enable coins on Bob side. Print the replies in case we need the "address".
    let bob_coins = block_on(enable_coins_eth_electrum(&mm_bob, ETH_DEV_NODES, None));
    log!("enable_coins (bob): {:?}", bob_coins);
    // issue sell request on Bob side by setting base/rel price
    log!("Issue bob sell requests");

    let bob_orders = [
        // (base, rel, price, volume, min_volume)
        ("RICK", "MORTY", "0.9", "0.9", None),
        ("RICK", "MORTY", "0.8", "0.9", None),
        ("RICK", "MORTY", "0.7", "0.9", Some("0.9")),
        ("RICK", "ETH", "0.8", "0.9", None),
        ("MORTY", "RICK", "0.8", "0.9", None),
        ("MORTY", "RICK", "0.9", "0.9", None),
        ("ETH", "RICK", "0.8", "0.9", None),
    ];
    for (base, rel, price, volume, min_volume) in bob_orders.iter() {
        let rc = block_on(mm_bob.rpc(&json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": base,
            "rel": rel,
            "price": price,
            "volume": volume,
            "min_volume": min_volume.unwrap_or("0.00777"),
            "cancel_previous": false,
        })))
        .unwrap();
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    }

    let mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("ALICE_TRADE_IP") .ok(),
            "rpcip": env::var ("ALICE_TRADE_IP") .ok(),
            "passphrase": "alice passphrase",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    block_on(mm_bob.wait_for_log(22., |log| {
        log.contains("DEBUG Handling IncludedTorelaysMesh message for peer")
    }))
    .unwrap();

    request_and_check_orderbook_depth(&mm_alice);
    // request RICK/MORTY orderbook to subscribe Alice
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    request_and_check_orderbook_depth(&mm_alice);

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

// https://github.com/KomodoPlatform/atomicDEX-API/issues/932
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_mm2_db_migration() {
    let bob_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();

    let coins = json!([rick_conf(), morty_conf(), eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let mm2_folder = new_mm2_temp_folder_path(None);
    let swaps_dir = mm2_folder.join(format!(
        "{}/SWAPS/STATS/MAKER",
        hex::encode(rmd160_from_passphrase(&bob_passphrase))
    ));
    std::fs::create_dir_all(&swaps_dir).unwrap();
    let swap_path = swaps_dir.join("5d02843e-d1b4-488d-aad0-114d82020453.json");
    let swap_json = r#"{"uuid":"5d02843e-d1b4-488d-aad0-114d82020453","events":[{"timestamp":1612780908136,"event":{"type":"Started","data":{"taker_coin":"MORTY-BEP20","maker_coin":"RICK-BEP20","taker":"ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fa","secret":"0000000000000000000000000000000000000000000000000000000000000000","secret_hash":"026bebc2e19c243d0940dd583c9573bf10377afd","my_persistent_pub":"037310a8fb9fd8f198a1a21db830252ad681fccda580ed4101f3f6bfb98b34fab5","lock_duration":7800,"maker_amount":"1","taker_amount":"1","maker_payment_confirmations":1,"maker_payment_requires_nota":false,"taker_payment_confirmations":1,"taker_payment_requires_nota":false,"maker_payment_lock":1612796508,"uuid":"5d02843e-d1b4-488d-aad0-114d82020453","started_at":1612780908,"maker_coin_start_block":793472,"taker_coin_start_block":797356,"maker_payment_trade_fee":null,"taker_payment_spend_trade_fee":null}}},{"timestamp":1612780924142,"event":{"type":"Negotiated","data":{"taker_payment_locktime":1612788708,"taker_pubkey":"03ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fa"}}},{"timestamp":1612780935156,"event":{"type":"TakerFeeValidated","data":{"tx_hex":"0400008085202f8901f425fbefe21f33ccb7b487df251191b27dfa7b639b04f60e5493c7ea41dbf149000000006b483045022100d5ec3e542175479bd4bd011e19b76a75e99f19cc49867e5bca9541950322c33a02207a4d1ffd674fb9760de79bb4929af44d66344b5e182de3c377186deebf6bf376012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff02bcf60100000000001976a914ca1e04745e8ca0c60d8c5881531d51bec470743f88ac5ce6f305000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588ac7c152160000000000000000000000000000000","tx_hash":"75323ab7acd64bd35242611fabaec560d9acf2e1f9ca28d3a4aba47a79fb49c4"}}},{"timestamp":1612780935174,"event":{"type":"MakerPaymentSent","data":{"tx_hex":"0400008085202f89028bef955e42107c562e4e02421f25c455723a701573f86c17b4d82e35a7d8f9f7020000006b483045022100b12fc9d95acca76bf5fd8d5c6acc288b454032ba4561b1c2b1f5f33b2cf2926d022017e561bc2cd93308848674b47b2e8ebd8f074ea78e32454d5fea6f08c0b1f1e40121037310a8fb9fd8f198a1a21db830252ad681fccda580ed4101f3f6bfb98b34fab5ffffffff5dfd0b24c0f7c3cf235868cf9a26ec49574764d135796fc4e7d20e95d55a8653000000006a47304402207c752d14601d1c99892f9d6c88c8ff2f93211640a65b2ee69172a16b908b21e402206f0b66684158445888271a849ab46258ad722496ee64fde055a6f44e36ed2ccc0121037310a8fb9fd8f198a1a21db830252ad681fccda580ed4101f3f6bfb98b34fab5ffffffff0300e1f5050000000017a9141b85c1a277f44f7d77d52b78e2ba70a0becc2ff9870000000000000000166a14026bebc2e19c243d0940dd583c9573bf10377afda7d26301000000001976a91486f747b28c60ad1130bdd3f84f48eeaf1801ca9888ac87152160000000000000000000000000000000","tx_hash":"27dafe553246553d54f909fbbded80e6d490fdb95ca7b6807d73eca45f0d7a22"}}},{"timestamp":1612780982221,"event":{"type":"TakerPaymentReceived","data":{"tx_hex":"0400008085202f8902c449fb797aa4aba4d328caf9e1f2acd960c5aeab1f614252d34bd6acb73a3275010000006a47304402200438c96bf457bacf906e94c98f91783129cb1c3a8f3d9355e1c39a9857fb2c6b02201d3c71b3f243f7a3c91bb9a15e80bb26e47bed04e798106a8af8dac61082ec41012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fafffffffff425fbefe21f33ccb7b487df251191b27dfa7b639b04f60e5493c7ea41dbf149010000006b483045022100efa00c742159b0b05433678aa95f0c8900adaddf5011bfaf56d6a7679aed428b022043f68efc3cb386dd10a65a2a3e8a904541c8f1ddbd7dddbcda2ccdd7938c5934012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faffffffff0300e1f5050000000017a914bc8e8f2648f7bb4dbd612f2e71dd7b23c54880b7870000000000000000166a14026bebc2e19c243d0940dd583c9573bf10377afd74c3e90b000000001976a914d55f0df6cb82630ad21a4e6049522a6f2b6c9d4588acb5152160000000000000000000000000000000","tx_hash":"94c8a1244421465b618a36e7647a270c7b2ef20eff3cd1317761cc242c49cc99"}}},{"timestamp":1612780982222,"event":{"type":"TakerPaymentWaitConfirmStarted"}},{"timestamp":1612781042265,"event":{"type":"TakerPaymentValidatedAndConfirmed"}},{"timestamp":1612781042272,"event":{"type":"TakerPaymentSpent","data":{"tx_hex":"0400008085202f890199cc492c24cc617731d13cff0ef22e7b0c277a64e7368a615b46214424a1c89400000000d84830450221008f38d29e7990bd694f2c4fd4c235fe00997da4e5133208d7c38e75e806d9be1702201ff1d598ceafc099dc4af7d4b91db535196f642cf31b5b5e386b28574a378b9b0120e8512e2afb02d3a90590d30095286e2293f51f9d4411ad87ef398ee8f566de43004c6b6304e4332160b1752103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36faac6782012088a914026bebc2e19c243d0940dd583c9573bf10377afd8821037310a8fb9fd8f198a1a21db830252ad681fccda580ed4101f3f6bfb98b34fab5ac68ffffffff0118ddf505000000001976a91486f747b28c60ad1130bdd3f84f48eeaf1801ca9888ace2072160000000000000000000000000000000","tx_hash":"d21173cca32b83ffe5d4cc327f7eff09496f52876614dbbfe7963284818ba9a1"}}},{"timestamp":1612781042273,"event":{"type":"TakerPaymentSpendConfirmStarted"}},{"timestamp":1612781207356,"event":{"type":"TakerPaymentSpendConfirmed"}},{"timestamp":1612781207357,"event":{"type":"Finished"}}],"maker_amount":"1","maker_coin":"RICK-BEP20","taker_amount":"1","taker_coin":"MORTY-BEP20","gui":"dexstats","mm_version":"19701cc87","success_events":["Started","Negotiated","TakerFeeValidated","MakerPaymentSent","TakerPaymentReceived","TakerPaymentWaitConfirmStarted","TakerPaymentValidatedAndConfirmed","TakerPaymentSpent","TakerPaymentSpendConfirmStarted","TakerPaymentSpendConfirmed","Finished"],"error_events":["StartFailed","NegotiateFailed","TakerFeeValidateFailed","MakerPaymentTransactionFailed","MakerPaymentDataSendFailed","MakerPaymentWaitConfirmFailed","TakerPaymentValidateFailed","TakerPaymentWaitConfirmFailed","TakerPaymentSpendFailed","TakerPaymentSpendConfirmFailed","MakerPaymentWaitRefundStarted","MakerPaymentRefunded","MakerPaymentRefundFailed"]}"#;
    std::fs::write(swap_path, swap_json.as_bytes()).unwrap();

    // if there is an issue with migration the start will fail
    MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 8999,
            "dht": "on",  // Enable DHT without delay.
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": bob_passphrase,
            "coins": coins,
            "rpc_password": "password",
            "i_am_seed": true,
            "dbdir": mm2_folder.display().to_string(),
        }),
        "password".into(),
        None,
    )
    .unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_current_mtp() {
    // KMD coin config used for this test
    let coins = json!([
        {"coin":"KMD","txversion":4,"overwintered":1,"txfee":10000,"protocol":{"type":"UTXO"}},
    ]);
    let passphrase = "cMhHM3PMpMrChygR4bLF7QsTdenhWpFrrmf2UezBG3eeFsz41rtL";

    let conf = Mm2TestConf::seednode(passphrase, &coins);
    let mm = MarketMakerIt::start(conf.conf, conf.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();

    let electrum = block_on(enable_electrum(
        &mm,
        "KMD",
        false,
        &[
            "electrum1.cipig.net:10001",
            "electrum2.cipig.net:10001",
            "electrum3.cipig.net:10001",
        ],
        None,
    ));
    log!("{:?}", electrum);

    let rc = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "get_current_mtp",
        "params": {
            "coin": "KMD",
        },
    })))
    .unwrap();

    // Test if request is successful before proceeding.
    assert!(rc.0.is_success());
    let mtp_result: Json = json::from_str(&rc.1).unwrap();
    // Test if mtp returns a u32 Number.
    assert!(mtp_result["result"]["mtp"].is_number());
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_public_key() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "rpc_password": "password",
            "coins": coins,
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    fn get_public_key_bot_rpc(mm: &MarketMakerIt) -> (StatusCode, String, HeaderMap) {
        block_on(mm.rpc(&json!({
                 "userpass": "password",
                 "mmrpc": "2.0",
                 "method": "get_public_key",
                 "params": {},
                 "id": 0})))
        .unwrap()
    }
    let resp = get_public_key_bot_rpc(&mm);

    // Must be 200
    assert_eq!(resp.0, 200);
    let v: RpcV2Response<GetPublicKeyResult> = serde_json::from_str(&resp.1).unwrap();
    assert_eq!(
        v.result.public_key,
        "022cd3021a2197361fb70b862c412bc8e44cff6951fa1de45ceabfdd9b4c520420"
    )
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_public_key_hash() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
    ]);

    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "rpc_password": "password",
            "coins": coins,
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());
    let resp = block_on(mm.rpc(&json!({
                 "userpass": "password",
                 "mmrpc": "2.0",
                 "method": "get_public_key_hash",
                 "params": {},
                 "id": 0})))
    .unwrap();

    // Must be 200
    assert_eq!(resp.0, StatusCode::OK);
    let v: RpcV2Response<GetPublicKeyHashResult> = serde_json::from_str(&resp.1).unwrap();
    // Public key hash must be "b506088aa2a3b4bb1da3a29bf00ce1a550ea1df9"
    assert_eq!(v.result.public_key_hash, "b506088aa2a3b4bb1da3a29bf00ce1a550ea1df9")
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_my_address_hd() {
    const PASSPHRASE: &str = "tank abandon bind salon remove wisdom net size aspect direct source fossil";

    let coins = json!([eth_testnet_conf()]);

    let conf = Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins);
    let mm = MarketMakerIt::start(conf.conf, conf.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("log path: {}", mm.log_path.display());

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "get_my_address",
        "params": {
            "coin": "ETH",
        }
    })))
    .unwrap();

    assert_eq!(resp.0, StatusCode::OK);
    let my_wallet_address: Json = json::from_str(&resp.1).unwrap();
    assert_eq!(
        my_wallet_address["result"]["wallet_address"],
        "0x1737F1FaB40c6Fd3dc729B51C0F97DB3297CCA93"
    )
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_orderbook_with_same_orderbook_ticker() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
        {"coin":"RICK-Utxo","asset":"RICK","orderbook_ticker":"RICK","rpcport":8923,"txversion":4,"protocol":{"type":"UTXO"}},
        // just a random contract address
        {"coin":"RICK-ERC20","orderbook_ticker":"RICK","decimals": 18,"protocol":{"type":"ERC20","protocol_data":{"platform":"ETH","contract_address":"0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9"}}},
    ]);

    let mm = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "rpc_password": "password",
            "coins": coins,
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "RICK-Utxo",
    })))
    .unwrap();
    assert!(
        rc.0.is_server_error(),
        "orderbook succeed but should have failed {}",
        rc.1
    );

    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "RICK-ERC20",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook {}", rc.1);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_conf_settings_in_orderbook() {
    let coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"required_confirmations":10,"requires_notarization":true,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"required_confirmations":5,"requires_notarization":false,"protocol":{"type":"UTXO"}},
    ]);

    let mm_bob = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "rpc_password": "password",
            "coins": coins,
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm_bob.mm_dump();
    log!("Log path: {}", mm_bob.log_path.display());

    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    log!("Issue set_price request for RICK/MORTY on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    log!("Issue set_price request for MORTY/RICK on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "MORTY",
        "rel": "RICK",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let mm_alice = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "alice passphrase",
            "rpc_password": "password",
            "coins": coins,
            "seednodes": [mm_bob.ip.to_string()],
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm_alice.mm_dump();
    log!("Log path: {}", mm_alice.log_path.display());

    log!(
        "enable_coins (alice): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_alice))
    );

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);

    assert_eq!(
        alice_orderbook.asks.len(),
        1,
        "Alice RICK/MORTY orderbook must have exactly 1 ask"
    );
    assert_eq!(
        alice_orderbook.asks[0].entry.conf_settings.as_ref().unwrap().base_confs,
        10
    );
    assert!(alice_orderbook.asks[0].entry.conf_settings.as_ref().unwrap().base_nota);
    assert_eq!(
        alice_orderbook.asks[0].entry.conf_settings.as_ref().unwrap().rel_confs,
        5
    );
    assert!(!alice_orderbook.asks[0].entry.conf_settings.as_ref().unwrap().rel_nota);

    assert_eq!(
        alice_orderbook.bids.len(),
        1,
        "Alice RICK/MORTY orderbook must have exactly 1 bid"
    );
    assert_eq!(
        alice_orderbook.bids[0].entry.conf_settings.as_ref().unwrap().base_confs,
        10
    );
    assert!(alice_orderbook.bids[0].entry.conf_settings.as_ref().unwrap().base_nota);
    assert_eq!(
        alice_orderbook.bids[0].entry.conf_settings.as_ref().unwrap().rel_confs,
        5
    );
    assert!(!alice_orderbook.bids[0].entry.conf_settings.as_ref().unwrap().rel_nota);

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn alice_can_see_confs_in_orderbook_after_sync() {
    let bob_coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"required_confirmations":10,"requires_notarization":true,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"required_confirmations":5,"requires_notarization":false,"protocol":{"type":"UTXO"}},
    ]);

    let mm_bob = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "bob passphrase",
            "rpc_password": "password",
            "coins": bob_coins,
            "i_am_seed": true,
        }),
        "password".into(),
        None,
    )
    .unwrap();
    // let (_dump_log, _dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    log!("Issue sell request on Bob side");
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": 0.9,
        "volume": "0.9",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "mmrpc": "2.0",
        "method": "get_public_key",
        "params": {},
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!get_public_key: {}", rc.1);
    let get_public_key_res: RpcV2Response<GetPublicKeyResult> = serde_json::from_str(&rc.1).unwrap();
    let bob_pubkey = get_public_key_res.result.public_key;

    // Alice coins don't have required_confirmations and requires_notarization set
    let alice_coins = json!([
        {"coin":"RICK","asset":"RICK","rpcport":8923,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}},
    ]);

    let mut mm_alice = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "passphrase": "alice passphrase",
            "rpc_password": "password",
            "coins": alice_coins,
            "seednodes": [mm_bob.ip.to_string()],
        }),
        "password".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    log!(
        "enable_coins (alice): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_alice))
    );

    // setting the price will trigger Alice's subscription to the orderbook topic
    // but won't request the actual orderbook
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "setprice",
        "base": "RICK",
        "rel": "MORTY",
        "price": "1",
        "volume": "0.1",
        "cancel_previous": false,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    block_on(
        mm_alice.wait_for_log((MIN_ORDER_KEEP_ALIVE_INTERVAL * 2) as f64, |log| {
            log.contains(&format!("Inserting order OrderbookItem {{ pubkey: \"{}\"", bob_pubkey))
        }),
    )
    .unwrap();

    log!("Get RICK/MORTY orderbook on Alice side");
    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let alice_orderbook: OrderbookResponse = json::from_str(&rc.1).unwrap();
    log!("Alice orderbook {:?}", alice_orderbook);
    assert_eq!(
        alice_orderbook.asks.len(),
        2,
        "Alice RICK/MORTY orderbook must have exactly 2 ask"
    );
    let bob_order_in_orderbook = alice_orderbook
        .asks
        .iter()
        .find(|entry| entry.entry.pubkey == bob_pubkey)
        .unwrap();
    assert_eq!(
        bob_order_in_orderbook.entry.conf_settings.as_ref().unwrap().base_confs,
        10
    );
    assert!(bob_order_in_orderbook.entry.conf_settings.as_ref().unwrap().base_nota);
    assert_eq!(
        bob_order_in_orderbook.entry.conf_settings.as_ref().unwrap().rel_confs,
        5
    );
    assert!(!bob_order_in_orderbook.entry.conf_settings.as_ref().unwrap().rel_nota);

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sign_verify_message_utxo() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";

    let coins = json!([
        {
            "coin":"RICK",
            "asset":"RICK",
            "rpcport":8923,
            "sign_message_prefix": "Komodo Signed Message:\n",
            "txversion":4,
            "overwintered":1,
            "protocol":{"type":"UTXO"}
        },
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": seed.to_string(),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    let response = block_on(sign_message(&mm_bob, "RICK"));
    let response: RpcV2Response<SignatureResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert_eq!(
        response.signature,
        "HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4="
    );

    let response = block_on(verify_message(
        &mm_bob,
        "RICK",
        "HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4=",
        "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW",
    ));
    let response: RpcV2Response<VerificationResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert!(response.is_valid);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sign_verify_message_utxo_segwit() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";

    let coins = json!([
        {
            "coin":"RICK",
            "asset":"RICK",
            "rpcport":8923,
            "sign_message_prefix": "Komodo Signed Message:\n",
            "txversion":4,
            "overwintered":1,
            "segwit": true,
            "address_format":{"format":"segwit"},
            "bech32_hrp": "rck",
            "protocol":{"type":"UTXO"}
        },
        {"coin":"MORTY","asset":"MORTY","rpcport":11608,"txversion":4,"overwintered":1,"protocol":{"type":"UTXO"}}
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": seed.to_string(),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_coins_rick_morty_electrum(&mm_bob))
    );

    let response = block_on(sign_message(&mm_bob, "RICK"));
    let response: RpcV2Response<SignatureResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert_eq!(
        response.signature,
        "HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4="
    );

    let response = block_on(verify_message(
        &mm_bob,
        "RICK",
        "HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4=",
        "rck1qqk4t2dppvmu9jja0z7nan0h464n5gve8h7nhay",
    ));
    let response: RpcV2Response<VerificationResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert!(response.is_valid);

    let response = block_on(verify_message(
        &mm_bob,
        "RICK",
        "HzetbqVj9gnUOznon9bvE61qRlmjH5R+rNgkxu8uyce3UBbOu+2aGh7r/GGSVFGZjRnaYC60hdwtdirTKLb7bE4=",
        "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW",
    ));
    let response: RpcV2Response<VerificationResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert!(response.is_valid);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sign_verify_message_eth() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";

    let coins = json!([
        {
            "coin": "ETH",
            "name": "ethereum",
            "fname": "Ethereum",
            "sign_message_prefix": "Ethereum Signed Message:\n",
            "rpcport": 80,
            "mm2": 1,
            "chain_id": 1,
            "required_confirmations": 3,
            "avg_blocktime": 0.25,
            "protocol": {"type": "ETH"}
        }
    ]);

    // start bob and immediately place the order
    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| s.parse::<i64>().unwrap()),
            "passphrase": seed.to_string(),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    // Enable coins on Bob side. Print the replies in case we need the "address".
    log!(
        "enable_coins (bob): {:?}",
        block_on(enable_native(&mm_bob, "ETH", ETH_DEV_NODES, None))
    );

    let response = block_on(sign_message(&mm_bob, "ETH"));
    let response: RpcV2Response<SignatureResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert_eq!(
        response.signature,
        "0xcdf11a9c4591fb7334daa4b21494a2590d3f7de41c7d2b333a5b61ca59da9b311b492374cc0ba4fbae53933260fa4b1c18f15d95b694629a7b0620eec77a938600"
    );

    let response = block_on(verify_message(&mm_bob, "ETH",
                                           "0xcdf11a9c4591fb7334daa4b21494a2590d3f7de41c7d2b333a5b61ca59da9b311b492374cc0ba4fbae53933260fa4b1c18f15d95b694629a7b0620eec77a938600",
                                           "0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29"));
    let response: RpcV2Response<VerificationResponse> = json::from_value(response).unwrap();
    let response = response.result;

    assert!(response.is_valid);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_no_login() {
    let coins = json!([rick_conf(), morty_conf()]);
    let seednode_passphrase = get_passphrase(&".env.seed", "BOB_PASSPHRASE").unwrap();
    let seednode_conf = Mm2TestConf::seednode(&seednode_passphrase, &coins);
    let seednode = MarketMakerIt::start(seednode_conf.conf, seednode_conf.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = seednode.mm_dump();
    log!("log path: {}", seednode.log_path.display());

    let no_login_conf = Mm2TestConf::no_login_node(&coins, &[&seednode.ip.to_string()]);
    let no_login_node = MarketMakerIt::start(no_login_conf.conf, no_login_conf.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = no_login_node.mm_dump();
    log!("log path: {}", no_login_node.log_path.display());

    block_on(enable_electrum_json(&seednode, RICK, false, doc_electrums(), None));
    block_on(enable_electrum_json(&seednode, MORTY, false, marty_electrums(), None));

    let orders = [
        // (base, rel, price, volume, min_volume)
        ("RICK", "MORTY", "0.9", "0.9", None),
        ("RICK", "MORTY", "0.8", "0.9", None),
        ("RICK", "MORTY", "0.7", "0.9", Some("0.9")),
        ("MORTY", "RICK", "0.8", "0.9", None),
        ("MORTY", "RICK", "0.9", "0.9", None),
    ];

    for (base, rel, price, volume, min_volume) in orders.iter() {
        let rc = block_on(seednode.rpc(&json! ({
            "userpass": seednode.userpass,
            "method": "setprice",
            "base": base,
            "rel": rel,
            "price": price,
            "volume": volume,
            "min_volume": min_volume.unwrap_or("0.00777"),
            "cancel_previous": false,
        })))
        .unwrap();
        assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    }

    let orderbook = block_on(no_login_node.rpc(&json! ({
        "userpass": no_login_node.userpass,
        "method": "orderbook",
        "base": "RICK",
        "rel": "MORTY",
    })))
    .unwrap();
    assert!(orderbook.0.is_success(), "!orderbook: {}", orderbook.1);
    let orderbook: OrderbookResponse = json::from_str(&orderbook.1).unwrap();
    assert_eq!(orderbook.asks.len(), 3);
    assert_eq!(orderbook.bids.len(), 2);

    let orderbook_v2 = block_on(no_login_node.rpc(&json! ({
        "userpass": no_login_node.userpass,
        "mmrpc": "2.0",
        "method": "orderbook",
        "params": {
            "base": "RICK",
            "rel": "MORTY",
        },
    })))
    .unwrap();
    assert!(orderbook_v2.0.is_success(), "!orderbook: {}", orderbook_v2.1);
    let orderbook_v2: RpcV2Response<OrderbookV2Response> = json::from_str(&orderbook_v2.1).unwrap();
    let orderbook_v2 = orderbook_v2.result;
    assert_eq!(orderbook_v2.asks.len(), 3);
    assert_eq!(orderbook_v2.bids.len(), 2);

    let best_orders = block_on(no_login_node.rpc(&json! ({
        "userpass": no_login_node.userpass,
        "method": "best_orders",
        "coin": "RICK",
        "action": "buy",
        "volume": "0.1",
    })))
    .unwrap();
    assert!(best_orders.0.is_success(), "!best_orders: {}", best_orders.1);
    let best_orders: BestOrdersResponse = json::from_str(&best_orders.1).unwrap();
    let best_morty_orders = best_orders.result.get("MORTY").unwrap();
    assert_eq!(1, best_morty_orders.len());
    let expected_price: BigDecimal = "0.8".parse().unwrap();
    assert_eq!(expected_price, best_morty_orders[0].price);

    let best_orders_v2 = block_on(no_login_node.rpc(&json! ({
        "userpass": no_login_node.userpass,
        "mmrpc": "2.0",
        "method": "best_orders",
        "params": {
            "coin": "RICK",
            "action": "buy",
            "request_by": {
                "type": "number",
                "value": 1
            }
        },
    })))
    .unwrap();
    assert!(best_orders_v2.0.is_success(), "!best_orders: {}", best_orders_v2.1);
    let best_orders_v2: RpcV2Response<BestOrdersV2Response> = json::from_str(&best_orders_v2.1).unwrap();
    let best_morty_orders = best_orders_v2.result.orders.get(MORTY).unwrap();
    assert_eq!(1, best_morty_orders.len());
    let expected_price: BigDecimal = "0.7".parse().unwrap();
    assert_eq!(expected_price, best_morty_orders[0].price.decimal);

    let orderbook_depth = block_on(no_login_node.rpc(&json! ({
        "userpass": no_login_node.userpass,
        "method": "orderbook_depth",
        "pairs":[["RICK","MORTY"]]
    })))
    .unwrap();
    assert!(
        orderbook_depth.0.is_success(),
        "!orderbook_depth: {}",
        orderbook_depth.1
    );
    let orderbook_depth: OrderbookDepthResponse = json::from_str(&orderbook_depth.1).unwrap();
    let orderbook_depth = orderbook_depth.result;
    assert_eq!(orderbook_depth[0].depth.asks, 3);
    assert_eq!(orderbook_depth[0].depth.bids, 2);

    let version = block_on(no_login_node.rpc(&json! ({
        "userpass": no_login_node.userpass,
        "method": "version",
    })))
    .unwrap();
    assert!(version.0.is_success(), "!version: {}", version.1);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_gui_storage_accounts_functionality() {
    let passphrase = "test_gui_storage passphrase";

    let conf = Mm2TestConf::seednode(passphrase, &json!([]));
    let mm = block_on(MarketMakerIt::start_async(conf.conf, conf.rpc_password, None)).unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::enable_account",
        "params": {
            "policy": "new",
            "account_id": {
                "type": "iguana"
            },
            "name": "My Iguana wallet",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::enable_account: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::add_account",
        "params": {
            "account_id": {
                "type": "hw",
                "device_pubkey": "1549128bbfb33b997949b4105b6a6371c998e212"
            },
            "description": "Any description",
            "name": "My HW",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::add_account: {}", resp.1);

    // Add `HD{1}` account that will be deleted later.
    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::add_account",
        "params": {
            "account_id": {
                "type": "hd",
                "account_idx": 1,
            },
            "name": "An HD account"
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::add_account: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::delete_account",
        "params": {
            "account_id": {
                "type": "hd",
                "account_idx": 1,
            }
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::delete_account: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::set_account_balance",
        "params": {
            "account_id": {
                "type": "hw",
                "device_pubkey": "1549128bbfb33b997949b4105b6a6371c998e212"
            },
            "balance_usd": "123.567",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::set_account_balance: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::set_account_name",
        "params": {
            "account_id": {
                "type": "iguana"
            },
            "name": "New Iguana account name",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::set_account_name: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::set_account_description",
        "params": {
            "account_id": {
                "type": "iguana"
            },
            "description": "Another description",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::set_account_description: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::get_accounts"
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::get_accounts: {}", resp.1);

    let actual: RpcV2Response<Vec<gui_storage::AccountWithEnabledFlag>> = json::from_str(&resp.1).unwrap();
    let expected = vec![
        gui_storage::AccountWithEnabledFlag {
            account_id: gui_storage::AccountId::Iguana,
            name: "New Iguana account name".to_string(),
            description: "Another description".to_string(),
            balance_usd: BigDecimal::from(0i32),
            enabled: true,
        },
        gui_storage::AccountWithEnabledFlag {
            account_id: gui_storage::AccountId::HW {
                device_pubkey: "1549128bbfb33b997949b4105b6a6371c998e212".to_string(),
            },
            name: "My HW".to_string(),
            description: "Any description".to_string(),
            balance_usd: BigDecimal::from(123567i32) / BigDecimal::from(1000i32),
            enabled: false,
        },
    ];
    assert_eq!(actual.result, expected);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_gui_storage_coins_functionality() {
    let passphrase = "test_gui_storage passphrase";

    let conf = Mm2TestConf::seednode(passphrase, &json!([]));
    let mm = block_on(MarketMakerIt::start_async(conf.conf, conf.rpc_password, None)).unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm.mm_dump();
    log!("Log path: {}", mm.log_path.display());

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::enable_account",
        "params": {
            "policy": "new",
            "account_id": {
                "type": "iguana"
            },
            "name": "My Iguana wallet",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::enable_account: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::add_account",
        "params": {
            "account_id": {
                "type": "hw",
                "device_pubkey": "1549128bbfb33b997949b4105b6a6371c998e212"
            },
            "description": "Any description",
            "name": "My HW",
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::add_account: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::activate_coins",
        "params": {
            "account_id": {
                "type": "iguana"
            },
            "tickers": ["RICK", "MORTY", "KMD"],
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::activate_coins: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::activate_coins",
        "params": {
            "account_id": {
                "type": "hw",
                "device_pubkey": "1549128bbfb33b997949b4105b6a6371c998e212"
            },
            "tickers": ["KMD", "MORTY", "BCH"],
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::activate_coins: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::deactivate_coins",
        "params": {
            "account_id": {
                "type": "hw",
                "device_pubkey": "1549128bbfb33b997949b4105b6a6371c998e212"
            },
            "tickers": ["BTC", "MORTY"],
        },
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::deactivate_coins: {}", resp.1);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::get_enabled_account",
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::get_enabled_account: {}", resp.1);
    let actual: RpcV2Response<gui_storage::AccountWithCoins> = json::from_str(&resp.1).unwrap();
    let expected = gui_storage::AccountWithCoins {
        account_id: gui_storage::AccountId::Iguana,
        name: "My Iguana wallet".to_string(),
        description: String::new(),
        balance_usd: BigDecimal::from(0i32),
        coins: vec!["RICK".to_string(), "MORTY".to_string(), "KMD".to_string()]
            .into_iter()
            .collect(),
    };
    assert_eq!(actual.result, expected);

    let resp = block_on(mm.rpc(&json!({
        "userpass": mm.userpass,
        "mmrpc": "2.0",
        "method": "gui_storage::get_account_coins",
        "params": {
            "account_id": {
                "type": "hw",
                "device_pubkey": "1549128bbfb33b997949b4105b6a6371c998e212"
            }
        }
    })))
    .unwrap();
    assert!(resp.0.is_success(), "!gui_storage::get_enabled_account: {}", resp.1);
    let actual: RpcV2Response<gui_storage::AccountCoins> = json::from_str(&resp.1).unwrap();
    let expected = gui_storage::AccountCoins {
        account_id: gui_storage::AccountId::HW {
            device_pubkey: "1549128bbfb33b997949b4105b6a6371c998e212".to_string(),
        },
        coins: vec!["KMD".to_string(), "BCH".to_string()].into_iter().collect(),
    };
    assert_eq!(actual.result, expected);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_enable_btc_with_sync_starting_header() {
    let coins = json!([btc_with_sync_starting_header()]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm_bob.mm_dump();
    log!("log path: {}", mm_bob.log_path.display());

    let utxo_bob = block_on(enable_utxo_v2_electrum(&mm_bob, "BTC", btc_electrums(), 80, None));
    log!("enable UTXO bob {:?}", utxo_bob);

    block_on(mm_bob.stop()).unwrap();
}

// This test is ignored because block headers sync and validation can take some time
#[test]
#[ignore]
#[cfg(not(target_arch = "wasm32"))]
fn test_btc_block_header_sync() {
    let coins = json!([btc_with_spv_conf()]);

    let mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm_bob.mm_dump();
    log!("log path: {}", mm_bob.log_path.display());

    let utxo_bob = block_on(enable_utxo_v2_electrum(&mm_bob, "BTC", btc_electrums(), 600, None));
    log!("enable UTXO bob {:?}", utxo_bob);

    block_on(mm_bob.stop()).unwrap();
}

// This test is ignored because block headers sync and validation can take some time
// Todo: this test is failing, need a small fix in calculating btc_testnet_next_block_bits, and to add each block header individually while validating it.
#[test]
#[ignore]
#[cfg(not(target_arch = "wasm32"))]
fn test_tbtc_block_header_sync() {
    let coins = json!([tbtc_with_spv_conf()]);

    let mm_bob = MarketMakerIt::start(
        json!({
            "gui": "nogui",
            "netid": 9998,
            "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
            "rpcip": env::var ("BOB_TRADE_IP") .ok(),
            "passphrase": "bob passphrase",
            "coins": coins,
            "rpc_password": "pass",
        }),
        "pass".into(),
        None,
    )
    .unwrap();
    let (_dump_log, _dump_dashboard) = mm_bob.mm_dump();
    log!("log path: {}", mm_bob.log_path.display());

    let utxo_bob = block_on(enable_utxo_v2_electrum(
        &mm_bob,
        "tBTC-TEST",
        tbtc_electrums(),
        100000,
        None,
    ));
    log!("enable UTXO bob {:?}", utxo_bob);

    block_on(mm_bob.stop()).unwrap();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_enable_coins_with_enable_hd() {
    const TX_HISTORY: bool = false;
    const PASSPHRASE: &str = "tank abandon bind salon remove wisdom net size aspect direct source fossil";

    let coins = json!([
        eth_testnet_conf(),
        eth_jst_testnet_conf(),
        rick_conf(),
        tqrc20_conf(),
        btc_segwit_conf(),
    ]);

    let path_to_address = StandardHDCoinAddress {
        account: 0,
        is_change: false,
        address_index: 0,
    };
    let conf_0 = Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins);
    let mm_hd_0 = MarketMakerIt::start(conf_0.conf, conf_0.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = mm_hd_0.mm_dump();
    log!("log path: {}", mm_hd_0.log_path.display());

    let eth = block_on(enable_native(
        &mm_hd_0,
        "ETH",
        ETH_DEV_NODES,
        Some(path_to_address.clone()),
    ));
    assert_eq!(eth.address, "0x1737F1FaB40c6Fd3dc729B51C0F97DB3297CCA93");
    let jst = block_on(enable_native(
        &mm_hd_0,
        "JST",
        ETH_DEV_NODES,
        Some(path_to_address.clone()),
    ));
    assert_eq!(jst.address, "0x1737F1FaB40c6Fd3dc729B51C0F97DB3297CCA93");
    let rick = block_on(enable_electrum(
        &mm_hd_0,
        "RICK",
        TX_HISTORY,
        DOC_ELECTRUM_ADDRS,
        Some(path_to_address.clone()),
    ));
    assert_eq!(rick.address, "RXNtAyDSsY3DS3VxTpJegzoHU9bUX54j56");
    let qrc20 = block_on(enable_qrc20(
        &mm_hd_0,
        "QRC20",
        QRC20_ELECTRUMS,
        "0xd362e096e873eb7907e205fadc6175c6fec7bc44",
        Some(path_to_address.clone()),
    ));
    assert_eq!(qrc20["address"].as_str(), Some("qRtCTiPHW9e6zH9NcRhjMVfq7sG37SvgrL"));
    let btc_segwit = block_on(enable_electrum(
        &mm_hd_0,
        "BTC-segwit",
        TX_HISTORY,
        TBTC_ELECTRUMS,
        Some(path_to_address),
    ));
    assert_eq!(btc_segwit.address, "bc1q6vyur5hjul2m0979aadd6u7ptuj9ac4gt0ha0c");

    let path_to_address = StandardHDCoinAddress {
        account: 0,
        is_change: false,
        address_index: 1,
    };
    let conf_1 = Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins);
    let mm_hd_1 = MarketMakerIt::start(conf_1.conf, conf_1.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = mm_hd_1.mm_dump();
    log!("log path: {}", mm_hd_1.log_path.display());

    let eth = block_on(enable_native(
        &mm_hd_1,
        "ETH",
        ETH_DEV_NODES,
        Some(path_to_address.clone()),
    ));
    assert_eq!(eth.address, "0xDe841899aB4A22E23dB21634e54920aDec402397");
    let jst = block_on(enable_native(
        &mm_hd_1,
        "JST",
        ETH_DEV_NODES,
        Some(path_to_address.clone()),
    ));
    assert_eq!(jst.address, "0xDe841899aB4A22E23dB21634e54920aDec402397");
    let rick = block_on(enable_electrum(
        &mm_hd_1,
        "RICK",
        TX_HISTORY,
        DOC_ELECTRUM_ADDRS,
        Some(path_to_address.clone()),
    ));
    assert_eq!(rick.address, "RVyndZp3ZrhGKSwHryyM3Kcz9aq2EJrW1z");
    let qrc20 = block_on(enable_qrc20(
        &mm_hd_1,
        "QRC20",
        QRC20_ELECTRUMS,
        "0xd362e096e873eb7907e205fadc6175c6fec7bc44",
        Some(path_to_address.clone()),
    ));
    assert_eq!(qrc20["address"].as_str(), Some("qY8FNq2ZDUh52BjNvaroFoeHdr3AAhqsxW"));
    let btc_segwit = block_on(enable_electrum(
        &mm_hd_1,
        "BTC-segwit",
        TX_HISTORY,
        TBTC_ELECTRUMS,
        Some(path_to_address),
    ));
    assert_eq!(btc_segwit.address, "bc1q6kxcwcrsm5z8pe940xxu294q7588mqvarttxcx");

    let path_to_address = StandardHDCoinAddress {
        account: 77,
        is_change: false,
        address_index: 7,
    };
    let conf_1 = Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins);
    let mm_hd_1 = MarketMakerIt::start(conf_1.conf, conf_1.rpc_password, None).unwrap();
    let (_dump_log, _dump_dashboard) = mm_hd_1.mm_dump();
    log!("log path: {}", mm_hd_1.log_path.display());

    let eth = block_on(enable_native(
        &mm_hd_1,
        "ETH",
        ETH_DEV_NODES,
        Some(path_to_address.clone()),
    ));
    assert_eq!(eth.address, "0xa420a4DBd8C50e6240014Db4587d2ec8D0cE0e6B");
    let jst = block_on(enable_native(
        &mm_hd_1,
        "JST",
        ETH_DEV_NODES,
        Some(path_to_address.clone()),
    ));
    assert_eq!(jst.address, "0xa420a4DBd8C50e6240014Db4587d2ec8D0cE0e6B");
    let rick = block_on(enable_electrum(
        &mm_hd_1,
        "RICK",
        TX_HISTORY,
        DOC_ELECTRUM_ADDRS,
        Some(path_to_address.clone()),
    ));
    assert_eq!(rick.address, "RLNu8gszQ8ENUrY3VSyBS2714CNVwn1f7P");
    let qrc20 = block_on(enable_qrc20(
        &mm_hd_1,
        "QRC20",
        QRC20_ELECTRUMS,
        "0xd362e096e873eb7907e205fadc6175c6fec7bc44",
        Some(path_to_address.clone()),
    ));
    assert_eq!(qrc20["address"].as_str(), Some("qREuDjyn7dzUPgnCkxPvALz9Szgy7diB5w"));
    let btc_segwit = block_on(enable_electrum(
        &mm_hd_1,
        "BTC-segwit",
        TX_HISTORY,
        TBTC_ELECTRUMS,
        Some(path_to_address),
    ));
    assert_eq!(btc_segwit.address, "bc1q0dxnd7afj997a40j86a8a6dq3xs3dwm7rkzams");
}

/// `shared_db_id` must be the same for Iguana and all HD accounts derived from the same passphrase.
#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_get_shared_db_id() {
    const PASSPHRASE: &str = "tank abandon bind salon remove wisdom net size aspect direct source fossil";
    const ANOTHER_PASSPHRASE: &str = "chair lyrics public brick beauty wine panther deer employ panther poet drip";

    let coins = json!([rick_conf()]);
    let confs = vec![
        Mm2TestConf::seednode(PASSPHRASE, &coins),
        Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins),
        Mm2TestConf::seednode_with_hd_account(PASSPHRASE, &coins),
    ];

    let mut shared_db_id = None;
    for conf in confs {
        let mm = MarketMakerIt::start(conf.conf, conf.rpc_password, None).unwrap();
        let actual = block_on(get_shared_db_id(&mm)).shared_db_id;
        if let Some(expected) = shared_db_id {
            assert_eq!(
                actual, expected,
                "'shared_db_id' must be the same for Iguana and all HD accounts derived from the same passphrase"
            );
        }
        shared_db_id = Some(actual);
    }

    let another_conf = Mm2TestConf::seednode(ANOTHER_PASSPHRASE, &coins);
    let mm_another = MarketMakerIt::start(another_conf.conf, another_conf.rpc_password, None).unwrap();
    let actual = block_on(get_shared_db_id(&mm_another)).shared_db_id;
    assert_ne!(
        Some(actual),
        shared_db_id,
        "'shared_db_id' must be different for different passphrases"
    );
}

#[test]
fn test_eth_swap_contract_addr_negotiation_same_fallback() {
    let bob_passphrase = get_passphrase!(".env.seed", "BOB_PASSPHRASE").unwrap();
    let alice_passphrase = get_passphrase!(".env.client", "ALICE_PASSPHRASE").unwrap();

    let coins = json!([eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let bob_conf = Mm2TestConf::seednode(&bob_passphrase, &coins);
    let mut mm_bob = MarketMakerIt::start(bob_conf.conf, bob_conf.rpc_password, None).unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    let alice_conf = Mm2TestConf::light_node(&alice_passphrase, &coins, &[&mm_bob.ip.to_string()]);
    let mut mm_alice = MarketMakerIt::start(alice_conf.conf, alice_conf.rpc_password, None).unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    dbg!(block_on(enable_eth_coin(
        &mm_bob,
        "ETH",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_DEV_TOKEN_CONTRACT,
        Some(ETH_DEV_SWAP_CONTRACT),
        false
    )));

    dbg!(block_on(enable_eth_coin(
        &mm_bob,
        "JST",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_DEV_TOKEN_CONTRACT,
        Some(ETH_DEV_SWAP_CONTRACT),
        false
    )));

    dbg!(block_on(enable_eth_coin(
        &mm_alice,
        "ETH",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_MAINNET_SWAP_CONTRACT,
        Some(ETH_DEV_SWAP_CONTRACT),
        false
    )));

    dbg!(block_on(enable_eth_coin(
        &mm_alice,
        "JST",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_MAINNET_SWAP_CONTRACT,
        Some(ETH_DEV_SWAP_CONTRACT),
        false
    )));

    let uuids = block_on(start_swaps(
        &mut mm_bob,
        &mut mm_alice,
        &[("ETH", "JST")],
        1.,
        1.,
        0.0001,
    ));

    // give few seconds for swap statuses to be saved
    thread::sleep(Duration::from_secs(3));

    let wait_until = get_utc_timestamp() + 30;
    let expected_contract = Json::from(ETH_DEV_SWAP_CONTRACT.trim_start_matches("0x"));

    block_on(wait_for_swap_contract_negotiation(
        &mm_bob,
        &uuids[0],
        expected_contract.clone(),
        wait_until,
    ));
    block_on(wait_for_swap_contract_negotiation(
        &mm_alice,
        &uuids[0],
        expected_contract,
        wait_until,
    ));
}

#[test]
fn test_eth_swap_negotiation_fails_maker_no_fallback() {
    let bob_passphrase = get_passphrase!(".env.seed", "BOB_PASSPHRASE").unwrap();
    let alice_passphrase = get_passphrase!(".env.client", "ALICE_PASSPHRASE").unwrap();

    let coins = json!([eth_testnet_conf(), eth_jst_testnet_conf(),]);

    let bob_conf = Mm2TestConf::seednode(&bob_passphrase, &coins);
    let mut mm_bob = MarketMakerIt::start(bob_conf.conf, bob_conf.rpc_password, None).unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());

    let alice_conf = Mm2TestConf::light_node(&alice_passphrase, &coins, &[&mm_bob.ip.to_string()]);
    let mut mm_alice = MarketMakerIt::start(alice_conf.conf, alice_conf.rpc_password, None).unwrap();

    let (_alice_dump_log, _alice_dump_dashboard) = mm_alice.mm_dump();
    log!("Alice log path: {}", mm_alice.log_path.display());

    dbg!(block_on(enable_eth_coin(
        &mm_bob,
        "ETH",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_DEV_TOKEN_CONTRACT,
        None,
        false
    )));

    dbg!(block_on(enable_eth_coin(
        &mm_bob,
        "JST",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_DEV_TOKEN_CONTRACT,
        None,
        false
    )));

    dbg!(block_on(enable_eth_coin(
        &mm_alice,
        "ETH",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_MAINNET_SWAP_CONTRACT,
        Some(ETH_DEV_SWAP_CONTRACT),
        false
    )));

    dbg!(block_on(enable_eth_coin(
        &mm_alice,
        "JST",
        ETH_DEV_NODES,
        // using arbitrary address
        ETH_MAINNET_SWAP_CONTRACT,
        Some(ETH_DEV_SWAP_CONTRACT),
        false
    )));

    let uuids = block_on(start_swaps(
        &mut mm_bob,
        &mut mm_alice,
        &[("ETH", "JST")],
        1.,
        1.,
        0.00001,
    ));

    // give few seconds for swap statuses to be saved
    thread::sleep(Duration::from_secs(3));

    let wait_until = get_utc_timestamp() + 30;
    block_on(wait_for_swap_negotiation_failure(&mm_bob, &uuids[0], wait_until));
    block_on(wait_for_swap_negotiation_failure(&mm_alice, &uuids[0], wait_until));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sign_raw_transaction_rick() {
    use mm2_test_helpers::for_tests::test_sign_raw_transaction_rpc_helper;

    let bob_seed = "UvCjJf4dKSs2vFGVtCnUTAhR5FTZGdg43DDRa9s7s5DV1sSDX14g";
    let coins = json!([rick_conf(), morty_conf()]);
    let conf = Mm2TestConf::seednode(bob_seed, &coins);

    // start bob
    let mm_bob = MarketMakerIt::start(conf.conf, conf.rpc_password, None).unwrap();

    let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
    log!("Bob log path: {}", mm_bob.log_path.display());
    // Enable coins on Bob side. Print the replies in case we need the "address".
    let coin_init_resp = block_on(enable_coins_rick_morty_electrum(&mm_bob));
    assert_eq!(
        coin_init_resp["RICK"].result, "success",
        "enable_coins failed with {}",
        coin_init_resp["RICK"].result
    );

    let response = block_on(test_sign_raw_transaction_rpc_helper(
        &mm_bob,
        StatusCode::OK,
        &json!({
            "coin": "RICK",
            "type": "UTXO",
            "tx": {
                "tx_hex": "0400008085202f89015794e93fbec895035c5321ad5b8b3f9212c25694d9cc67de2093114ab4bd69530000000000ffffffff01605af405000000001976a914b506088aa2a3b4bb1da3a29bf00ce1a550ea1df988ac00000000c1d31e000000000000000000000000",
                "prev_txns": [{
                    "tx_hash": "5794e93fbec895035c5321ad5b8b3f9212c25694d9cc67de2093114ab4bd6953", //"5369bdb44a119320de67ccd99456c212923f8b5bad21535c0395c8be3fe99457",
                    "index": 0,
                    "script_pub_key": "76a914b506088aa2a3b4bb1da3a29bf00ce1a550ea1df988ac",
                    "amount": 1.00000000,
                }]
            }
        }),
    ));
    assert_eq!(response["result"]["tx_hex"], Json::from("0400008085202f89015794e93fbec895035c5321ad5b8b3f9212c25694d9cc67de2093114ab4bd6953000000006a47304402204d5793070a4f35946a7be6df0ff5e6db4e8e50c37d515dc24e2a70481b0d58d102205c144d2a504d2e59ac939472d90f91927b013b8b799bfd5fab3b71fbbb0d3b970121022cd3021a2197361fb70b862c412bc8e44cff6951fa1de45ceabfdd9b4c520420ffffffff01605af405000000001976a914b506088aa2a3b4bb1da3a29bf00ce1a550ea1df988ac00000000c1d31e000000000000000000000000"));
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn test_sign_raw_transaction_p2wpkh() {
    use mm2_test_helpers::for_tests::test_sign_raw_transaction_rpc_helper;

    let bob_seed = "cNPm5PHMLfc4WPvsbGCpNMfVcoueVNZwJeW4fEfW3QWf8QaAT2Hd";
    let coin = tbtc_segwit_conf();
    let conf = Mm2TestConf::seednode(bob_seed, &json!([coin]));

    // start bob
    let mm_bob = MarketMakerIt::start(conf.conf, conf.rpc_password, None).unwrap();
    // Enable coins on Bob side. Print the replies in case we need the "address".
    let coin_init_resp = block_on(enable_electrum(&mm_bob, "tBTC-Segwit", false, TBTC_ELECTRUMS, None));
    assert_eq!(
        coin_init_resp.result, "success",
        "enable_coins failed with {}",
        coin_init_resp.result
    );

    let response = block_on(test_sign_raw_transaction_rpc_helper(
        &mm_bob,
        StatusCode::OK,
        &json!({
            "coin": "tBTC-Segwit",
            "type": "UTXO",
            "tx": {
                "tx_hex": "02000000010d23d763f12d77a337cc16df2696ac3f48552dda373c9977fa1f5dd8d5025cb20100000000fdffffff01f40100000000000016001488accd2145b7232b958db5cdf09336ad619541e200000000",
                "prev_txns": [{
                    "tx_hash": "0d23d763f12d77a337cc16df2696ac3f48552dda373c9977fa1f5dd8d5025cb2",
                    "index": 1,
                    "script_pub_key": "001449e3b6b4684c4d4a914b29411af51843c59bfff0",
                    "amount": 0.00001000,
                }]
            }
        }),
    ));
    assert_eq!(response["result"]["tx_hex"], Json::from("020000000001010d23d763f12d77a337cc16df2696ac3f48552dda373c9977fa1f5dd8d5025cb20100000000fdffffff01f40100000000000016001488accd2145b7232b958db5cdf09336ad619541e2024730440220156d185b3fb21725c040b7ddcf84bf862b46f079bb66067eef1941023b8451e602204d877ac51b74932dea34c20874fa8112b3636eb506ac429548f7c05fe54e3faf0121039ad38f67dbc22cf5a6bd48b26920d9fac71681836faf80a9a678ddbaa0fe92f800000000"));

    // bad request: spend from two different addresses
    let response = block_on(test_sign_raw_transaction_rpc_helper(
        &mm_bob,
        StatusCode::BAD_REQUEST,
        &json!({
            "coin": "tBTC-Segwit",
            "type": "UTXO",
            "tx": {
                "tx_hex": "02000000020d23d763f12d77a337cc16df2696ac3f48552dda373c9977fa1f5dd8d5025cb20100000000fdffffff257c76e76a42c6833d137230ce94c0300178f3f84bd1ef2d1f8fa53d062fc9960000000000fdffffff01f40100000000000016001488accd2145b7232b958db5cdf09336ad619541e200000000",
                "prev_txns": [{
                    "tx_hash": "0d23d763f12d77a337cc16df2696ac3f48552dda373c9977fa1f5dd8d5025cb2",
                    "index": 1,
                    "script_pub_key": "001449e3b6b4684c4d4a914b29411af51843c59bfff0",
                    "amount": 0.00001000,
                }, {
                    "tx_hash": "96c92f063da58f1f2defd14bf8f3780130c094ce3072133d83c6426ae7767c25",
                    "index": 0,
                    "script_pub_key": "00146538caea0d5579f5b9f4e19ddbe2d6c663f3ea56",
                    "amount": 0.00002306,
                }]
            }
        }),
    ));
    assert_eq!(
        response["error"],
        Json::from("Invalid param: spends are from same address only")
    );
}

#[cfg(all(feature = "run-device-tests", not(target_arch = "wasm32")))]
mod trezor_tests {
    use super::enable_utxo_v2_electrum;
    use coins::utxo::for_tests::test_withdraw_init_loop;
    use coins::utxo::{utxo_standard::UtxoStandardCoin, UtxoActivationParams};
    use coins_activation::{for_tests::init_standalone_coin_loop, InitStandaloneCoinReq};
    use common::executor::Timer;
    use common::serde::Deserialize;
    use common::{block_on, log, now_ms, wait_until_ms};
    use crypto::hw_rpc_task::HwRpcTaskAwaitingStatus;
    use crypto::CryptoCtx;
    use mm2_core::mm_ctx::MmArc;
    use mm2_main::mm2::init_hw::init_trezor_user_action;
    use mm2_main::mm2::init_hw::{init_trezor, init_trezor_status, InitHwRequest, InitHwResponse};
    use mm2_test_helpers::electrums::tbtc_electrums;
    use mm2_test_helpers::for_tests::{init_trezor_rpc, init_trezor_status_rpc, init_trezor_user_action_rpc,
                                      init_withdraw, mm_ctx_with_custom_db_with_conf, tbtc_legacy_conf,
                                      tbtc_segwit_conf, withdraw_status, MarketMakerIt, Mm2TestConf};
    use mm2_test_helpers::structs::{InitTaskResult, RpcV2Response, TransactionDetails, WithdrawStatus};
    use rpc_task::{rpc_common::RpcTaskStatusRequest, RpcTaskStatus};
    use serde_json::{self as json, json, Value as Json};
    use std::io::{stdin, stdout, BufRead, Write};

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, tag = "status", content = "details")]
    pub enum InitTrezorStatus {
        Ok(InitHwResponse),
        Error(Json),
        InProgress(Json),
        UserActionRequired(Json),
    }

    pub async fn mm_ctx_with_trezor(conf: Json) -> MmArc {
        let ctx = mm_ctx_with_custom_db_with_conf(Some(conf));

        CryptoCtx::init_with_iguana_passphrase(ctx.clone(), "123456").unwrap(); // for now we need passphrase seed for init
        let req: InitHwRequest = serde_json::from_value(json!({ "device_pubkey": null })).unwrap();
        let res = match init_trezor(ctx.clone(), req).await {
            Ok(res) => res,
            _ => {
                panic!("cannot init trezor");
            },
        };

        let task_id = res.task_id;
        loop {
            let status_req = RpcTaskStatusRequest {
                task_id,
                forget_if_finished: false,
            };
            match init_trezor_status(ctx.clone(), status_req).await {
                Ok(res) => {
                    log!("trezor init status={:?}", serde_json::to_string(&res).unwrap());
                    match res {
                        RpcTaskStatus::Ok(_) => {
                            log!("device initialized");
                            break;
                        },
                        RpcTaskStatus::Error(_) => {
                            log!("device in error state");
                            break;
                        },
                        RpcTaskStatus::InProgress(_) => log!("trezor init in progress"),
                        RpcTaskStatus::UserActionRequired(device_req) => {
                            log!("device is waiting for user action");
                            match device_req {
                                HwRpcTaskAwaitingStatus::EnterTrezorPin => {
                                    print!("Enter pin:");
                                    let _ = stdout().flush();
                                    let pin = stdin().lock().lines().next().unwrap().unwrap(); // read pin from console
                                    let pin_req = serde_json::from_value(json!({
                                        "task_id": task_id,
                                        "user_action": {
                                            "action_type": "TrezorPin",
                                            "pin": pin
                                        }
                                    }))
                                    .unwrap();
                                    let _ = init_trezor_user_action(ctx.clone(), pin_req).await;
                                },
                                _ => {
                                    panic!("Trezor passphrase is not supported in tests");
                                },
                            }
                        },
                    }
                },
                _ => {
                    panic!("cannot get trezor status");
                },
            };
            Timer::sleep(5.).await
        }
        ctx
    }

    /// Tool to run withdraw directly with trezor device or emulator (no rpc version, added for easier debugging)
    /// run cargo test with '--features run-device-tests' option
    /// to use trezor emulator also add '--features trezor-udp' option to cargo params
    #[test]
    fn test_withdraw_from_trezor_segwit_no_rpc() {
        let ticker = "tBTC-Segwit";
        let mut coin_conf = tbtc_segwit_conf();
        coin_conf["trezor_coin"] = "Testnet".into();
        let mm_conf = json!({ "coins": [coin_conf] });

        let ctx = block_on(mm_ctx_with_trezor(mm_conf));
        let enable_req = json!({
            "method": "electrum",
            "coin": ticker,
            "servers": tbtc_electrums(),
            "priv_key_policy": "Trezor",
        });
        let activation_params = UtxoActivationParams::from_legacy_req(&enable_req).unwrap();
        let request: InitStandaloneCoinReq<UtxoActivationParams> = json::from_value(json!({
            "ticker": ticker,
            "activation_params": activation_params
        }))
        .unwrap();

        block_on(init_standalone_coin_loop::<UtxoStandardCoin>(ctx.clone(), request))
            .expect("coin activation must be successful");

        let tx_details = block_on(test_withdraw_init_loop(
            ctx,
            ticker,
            "tb1q3zkv6g29ku3jh9vdkhxlpyek44se2s0zrv7ctn",
            "0.00001",
            "m/84'/1'/0'/0/0",
        ))
        .expect("withdraw must end successfully");
        log!("tx_hex={}", serde_json::to_string(&tx_details.tx_hex).unwrap());
    }

    /// Helper to init trezor and wait for completion
    pub async fn init_trezor_loop_rpc(mm: &MarketMakerIt, coin: &str, timeout: u64) -> InitHwResponse {
        let init = init_trezor_rpc(mm, coin).await;
        let init: RpcV2Response<InitTaskResult> = json::from_value(init).unwrap();
        let timeout = wait_until_ms(timeout * 1000);

        loop {
            if now_ms() > timeout {
                panic!("{} init_trezor_rpc timed out", coin);
            }

            let ret = init_trezor_status_rpc(mm, init.result.task_id).await;
            log!("init_trezor_status_rpc: {:?}", ret);
            let ret: RpcV2Response<InitTrezorStatus> = json::from_value(ret).unwrap();
            match ret.result {
                InitTrezorStatus::Ok(result) => break result,
                InitTrezorStatus::Error(e) => panic!("{} trezor initialization error {:?}", coin, e),
                InitTrezorStatus::UserActionRequired(device_req) => {
                    log!("device is waiting for user action");
                    let device_req = json::from_value(device_req).unwrap();
                    match device_req {
                        HwRpcTaskAwaitingStatus::EnterTrezorPin => {
                            print!("Enter pin:");
                            let _ = stdout().flush();
                            let pin = stdin().lock().lines().next().unwrap().unwrap(); // read pin from console
                            let pin_action = json!({
                                "action_type": "TrezorPin",
                                "pin": pin
                            });
                            let _ = init_trezor_user_action_rpc(mm, init.result.task_id, pin_action).await;
                        },
                        _ => {
                            panic!("Trezor passphrase is not supported in tests");
                        },
                    }
                },
                _ => Timer::sleep(1.).await,
            }
        }
    }

    /// Helper to run init withdraw and wait for completion
    async fn init_withdraw_loop_rpc(
        mm: &MarketMakerIt,
        coin: &str,
        to: &str,
        amount: &str,
        from: Option<Json>,
    ) -> TransactionDetails {
        let init = init_withdraw(mm, coin, to, amount, from).await;
        let init: RpcV2Response<InitTaskResult> = json::from_value(init).unwrap();
        let timeout = wait_until_ms(150000);

        loop {
            if now_ms() > timeout {
                panic!("{} init_withdraw timed out", coin);
            }

            let status = withdraw_status(mm, init.result.task_id).await;
            log!("Withdraw status {}", json::to_string(&status).unwrap());
            let status: RpcV2Response<WithdrawStatus> = json::from_value(status).unwrap();
            match status.result {
                WithdrawStatus::Ok(result) => break result,
                WithdrawStatus::Error(e) => panic!("{} withdraw error {:?}", coin, e),
                _ => Timer::sleep(1.).await,
            }
        }
    }

    /// Tool to run withdraw rpc from trezor device or emulator segwit account
    /// run cargo test with '--features run-device-tests' option
    /// to use trezor emulator also add '--features trezor-udp' option to cargo params
    #[test]
    fn test_withdraw_from_trezor_segwit_rpc() {
        let default_passphrase = "123"; // TODO: remove when we allow hardware wallet init w/o seed
        let ticker = "tBTC-Segwit";
        let mut coin_conf = tbtc_segwit_conf();
        coin_conf["trezor_coin"] = "Testnet".into();

        // start bob
        let conf = Mm2TestConf::seednode(default_passphrase, &json!([coin_conf]));
        let mm_bob = block_on(MarketMakerIt::start_async(conf.conf, conf.rpc_password, None)).unwrap();

        let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
        log!("Bob log path: {}", mm_bob.log_path.display());

        block_on(init_trezor_loop_rpc(&mm_bob, ticker, 60));

        let utxo_bob = block_on(enable_utxo_v2_electrum(
            &mm_bob,
            ticker,
            tbtc_electrums(),
            80,
            Some("Trezor"),
        ));
        log!("enable UTXO bob {:?}", utxo_bob);

        let tx_details = block_on(init_withdraw_loop_rpc(
            &mm_bob,
            ticker,
            "tb1q3zkv6g29ku3jh9vdkhxlpyek44se2s0zrv7ctn",
            "0.00001",
            Some(json!({"derivation_path": "m/84'/1'/0'/0/0"})),
        ));
        log!("tx_hex={}", serde_json::to_string(&tx_details.tx_hex).unwrap());
        block_on(mm_bob.stop()).unwrap();
    }

    /// Tool to run withdraw rpc from trezor device or emulator p2pkh account
    /// run cargo test with '--features run-device-tests' option
    /// to use trezor emulator also add '--features trezor-udp' option to cargo params
    #[test]
    fn test_withdraw_from_trezor_p2pkh_rpc() {
        let default_passphrase = "123"; // TODO: remove when we allow hardware wallet init w/o seed
        let ticker = "tBTC";
        let mut coin_conf = tbtc_legacy_conf();
        coin_conf["trezor_coin"] = "Testnet".into();
        coin_conf["derivation_path"] = "m/44'/1'".into();

        // start bob
        let conf = Mm2TestConf::seednode(default_passphrase, &json!([coin_conf]));
        let mm_bob = block_on(MarketMakerIt::start_async(conf.conf, conf.rpc_password, None)).unwrap();

        let (_bob_dump_log, _bob_dump_dashboard) = mm_bob.mm_dump();
        log!("Bob log path: {}", mm_bob.log_path.display());

        block_on(init_trezor_loop_rpc(&mm_bob, ticker, 60));

        let utxo_bob = block_on(enable_utxo_v2_electrum(
            &mm_bob,
            ticker,
            tbtc_electrums(),
            80,
            Some("Trezor"),
        ));
        log!("enable UTXO bob {:?}", utxo_bob);

        let tx_details = block_on(init_withdraw_loop_rpc(
            &mm_bob,
            ticker,
            "miuSj7rXDxbaHsqf1GmoKkygTBnoi3iwzj",
            "0.00001",
            Some(json!({"derivation_path": "m/44'/1'/0'/0/0"})),
        ));
        log!("tx_hex={}", serde_json::to_string(&tx_details.tx_hex).unwrap());
        block_on(mm_bob.stop()).unwrap();
    }
}
