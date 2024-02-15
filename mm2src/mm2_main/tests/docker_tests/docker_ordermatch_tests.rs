use crate::generate_utxo_coin_with_random_privkey;
use crate::integration_tests_common::enable_native;
use common::block_on;
use mm2_number::BigDecimal;
use mm2_rpc::data::legacy::OrderbookResponse;
use mm2_test_helpers::for_tests::{mm_dump, MarketMakerIt};
use mm2_test_helpers::structs::{BestOrdersResponse, BestOrdersV2Response, BuyOrSellRpcResult, MyOrdersRpcResult,
                                OrderbookDepthResponse, RpcV2Response, SetPriceResponse};
use serde_json::Value as Json;
use std::thread;
use std::time::Duration;

fn check_asks_num(mm: &MarketMakerIt, base: &str, rel: &str, expected: usize) {
    log!("Get {}/{} orderbook", base, rel);
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "orderbook",
        "base": base,
        "rel": rel,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);
    let orderbook: OrderbookResponse = serde_json::from_str(&rc.1).unwrap();
    log!("orderbook {:?}", orderbook);
    assert_eq!(
        orderbook.asks.len(),
        expected,
        "{}/{} orderbook must have exactly {} ask(s)",
        base,
        rel,
        expected
    );
}

fn check_bids_num(mm: &MarketMakerIt, base: &str, rel: &str, expected: usize) {
    log!("Get {}/{} orderbook", base, rel);
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "orderbook",
        "base": base,
        "rel": rel,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);
    let orderbook: OrderbookResponse = serde_json::from_str(&rc.1).unwrap();
    log!("orderbook {:?}", orderbook);
    assert_eq!(
        orderbook.bids.len(),
        expected,
        "{}/{} orderbook must have exactly {} bid(s)",
        base,
        rel,
        expected
    );
}

fn check_orderbook_depth(mm: &MarketMakerIt, pairs: &[(&str, &str)], expected: &[(usize, usize)]) {
    log!("Get {:?} orderbook depth", pairs);
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "orderbook_depth",
        "pairs": pairs,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook_depth: {}", rc.1);
    let orderbook_depth: OrderbookDepthResponse = serde_json::from_str(&rc.1).unwrap();
    log!("orderbook depth {:?}", orderbook_depth);
    for (pair, expected_depth) in pairs.iter().zip(expected) {
        let actual_depth = orderbook_depth
            .result
            .iter()
            .find(|pair_with_depth| pair.0 == pair_with_depth.pair.0 && pair.1 == pair_with_depth.pair.1)
            .unwrap_or_else(|| panic!("Orderbook depth result doesn't contain pair {:?}", pair));

        assert_eq!(
            actual_depth.depth.asks, expected_depth.0,
            "expected {} asks for pair {:?}",
            expected_depth.0, actual_depth.pair,
        );
        assert_eq!(
            actual_depth.depth.bids, expected_depth.1,
            "expected {} bids for pair {:?}",
            expected_depth.1, actual_depth.pair,
        );
    }
}

fn check_best_orders(
    mm: &MarketMakerIt,
    action: &str,
    for_coin: &str,
    ticker_in_response: &str,
    expected_num_orders: usize,
) {
    log!("Get best orders for {}", for_coin);
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "best_orders",
        "coin": for_coin,
        "action": action,
        "volume": 1,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!best_orders: {}", rc.1);
    let best_orders: BestOrdersResponse = serde_json::from_str(&rc.1).unwrap();
    let orders = best_orders
        .result
        .get(ticker_in_response)
        .unwrap_or_else(|| panic!("No orders for ticker {}", ticker_in_response));

    assert_eq!(orders.len(), expected_num_orders);
}

fn check_best_orders_v2_by_number(
    mm: &MarketMakerIt,
    action: &str,
    for_coin: &str,
    ticker_in_response: &str,
    expected_num_orders: usize,
) {
    log!("Get best orders for {}", for_coin);
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "best_orders",
        "mmrpc": "2.0",
        "params": {
            "coin": for_coin,
            "action": action,
            "request_by": {
                "type": "number",
                "value": 1
            }
        }
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!best_orders: {}", rc.1);
    let best_orders: RpcV2Response<BestOrdersV2Response> = serde_json::from_str(&rc.1).unwrap();
    let orders = best_orders
        .result
        .orders
        .get(ticker_in_response)
        .unwrap_or_else(|| panic!("No orders for ticker {}", ticker_in_response));
    assert_eq!(orders.len(), expected_num_orders);
}

fn check_best_orders_v2_by_volume(
    mm: &MarketMakerIt,
    action: &str,
    for_coin: &str,
    ticker_in_response: &str,
    expected_num_orders: usize,
) {
    log!("Get best orders for {}", for_coin);
    let rc = block_on(mm.rpc(&json! ({
        "userpass": mm.userpass,
        "method": "best_orders",
        "mmrpc": "2.0",
        "params": {
            "coin": for_coin,
            "action": action,
            "request_by": {
                "type": "volume",
                "value": 1
            }
        }
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!best_orders: {}", rc.1);
    let best_orders: RpcV2Response<BestOrdersV2Response> = serde_json::from_str(&rc.1).unwrap();
    let orders = best_orders
        .result
        .orders
        .get(ticker_in_response)
        .unwrap_or_else(|| panic!("No orders for ticker {}", ticker_in_response));
    assert_eq!(orders.len(), expected_num_orders);
}

#[test]
fn test_ordermatch_custom_orderbook_ticker_both_on_maker() {
    let (_ctx, _, bob_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000.into());
    let (_ctx, _, alice_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN1", 2000.into());
    let coins = json! ([
        {"coin":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN-Custom", "orderbook_ticker":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1-Custom", "orderbook_ticker":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
    ]);
    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "seednodes": vec![format!("{}", mm_bob.ip)],
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);

    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN-Custom", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN1-Custom", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN1", &[], None)));
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "MYCOIN-Custom",
        "rel": "MYCOIN1-Custom",
        "price": 1,
        "max": true,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    let sell_result: SetPriceResponse = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(sell_result.result.base, "MYCOIN-Custom");
    assert_eq!(sell_result.result.rel, "MYCOIN1-Custom");
    assert_eq!(sell_result.result.base_orderbook_ticker, Some("MYCOIN".to_owned()));
    assert_eq!(sell_result.result.rel_orderbook_ticker, Some("MYCOIN1".to_owned()));

    // check bob orders
    check_asks_num(&mm_bob, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_bob, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_bob, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_bob, "MYCOIN1", "MYCOIN", 1);

    // check multiple RPCs on alice side
    check_best_orders(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    check_asks_num(&mm_alice, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_alice, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_alice, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_alice, "MYCOIN1", "MYCOIN", 1);

    // check orderbook depth again after subscription to the topic
    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": "MYCOIN",
        "rel": "MYCOIN1",
        "price": 1,
        "volume": "999.99999",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);

    block_on(mm_bob.wait_for_log(22., |log| {
        log.contains("Entering the maker_swap_loop MYCOIN-Custom/MYCOIN1-Custom")
    }))
    .unwrap();
    block_on(mm_alice.wait_for_log(22., |log| log.contains("Entering the taker_swap_loop MYCOIN/MYCOIN1"))).unwrap();

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
fn test_ordermatch_custom_orderbook_ticker_both_on_taker() {
    let (_ctx, _, bob_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000.into());
    let (_ctx, _, alice_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN1", 2000.into());

    let coins = json! ([
        {"coin":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN-Custom", "orderbook_ticker":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1-Custom", "orderbook_ticker":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
    ]);
    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "seednodes": vec![format!("{}", mm_bob.ip)],
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);

    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN1", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN-Custom", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN1-Custom", &[], None)));
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "MYCOIN",
        "rel": "MYCOIN1",
        "price": 1,
        "max": true,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);

    // check orderbooks on bob side
    check_asks_num(&mm_bob, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_bob, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_bob, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_bob, "MYCOIN1", "MYCOIN", 1);

    // check multiple RPCs on alice side
    check_best_orders(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    check_asks_num(&mm_alice, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_alice, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_alice, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_alice, "MYCOIN1", "MYCOIN", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": "MYCOIN-Custom",
        "rel": "MYCOIN1-Custom",
        "price": 1,
        "volume": "999.99999",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);
    let buy_result: BuyOrSellRpcResult = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(buy_result.result.base, "MYCOIN-Custom");
    assert_eq!(buy_result.result.rel, "MYCOIN1-Custom");
    assert_eq!(buy_result.result.base_orderbook_ticker, Some("MYCOIN".to_owned()));
    assert_eq!(buy_result.result.rel_orderbook_ticker, Some("MYCOIN1".to_owned()));

    block_on(mm_bob.wait_for_log(22., |log| log.contains("Entering the maker_swap_loop MYCOIN/MYCOIN1"))).unwrap();
    block_on(mm_alice.wait_for_log(22., |log| {
        log.contains("Entering the taker_swap_loop MYCOIN-Custom/MYCOIN1-Custom")
    }))
    .unwrap();

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
fn test_ordermatch_custom_orderbook_ticker_mixed_case_one() {
    let (_ctx, _, bob_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000.into());
    let (_ctx, _, alice_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN1", 2000.into());

    let coins = json! ([
        {"coin":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN-Custom", "orderbook_ticker":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1-Custom", "orderbook_ticker":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
    ]);
    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "seednodes": vec![format!("{}", mm_bob.ip)],
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);

    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN-Custom", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN1", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN1-Custom", &[], None)));
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "MYCOIN-Custom",
        "rel": "MYCOIN1",
        "price": 1,
        "max": true,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let set_price: SetPriceResponse = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(set_price.result.base, "MYCOIN-Custom");
    assert_eq!(set_price.result.rel, "MYCOIN1");
    assert_eq!(set_price.result.base_orderbook_ticker, Some("MYCOIN".to_owned()));
    assert!(set_price.result.rel_orderbook_ticker.is_none());

    // check orderbooks on bob side
    check_asks_num(&mm_bob, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_bob, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_bob, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_bob, "MYCOIN1", "MYCOIN", 1);

    // check multiple RPCs on alice side
    check_best_orders(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    check_asks_num(&mm_alice, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_alice, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_alice, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_alice, "MYCOIN1", "MYCOIN", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": "MYCOIN",
        "rel": "MYCOIN1-Custom",
        "price": 1,
        "volume": "999.99999",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);
    let buy_result: BuyOrSellRpcResult = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(buy_result.result.base, "MYCOIN");
    assert_eq!(buy_result.result.rel, "MYCOIN1-Custom");
    assert!(buy_result.result.base_orderbook_ticker.is_none());
    assert_eq!(buy_result.result.rel_orderbook_ticker, Some("MYCOIN1".to_owned()));

    block_on(mm_bob.wait_for_log(22., |log| {
        log.contains("Entering the maker_swap_loop MYCOIN-Custom/MYCOIN1")
    }))
    .unwrap();
    block_on(mm_alice.wait_for_log(22., |log| {
        log.contains("Entering the taker_swap_loop MYCOIN/MYCOIN1-Custom")
    }))
    .unwrap();

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

#[test]
fn test_ordermatch_custom_orderbook_ticker_mixed_case_two() {
    let (_ctx, _, bob_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000.into());
    let (_ctx, _, alice_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN1", 2000.into());

    let coins = json! ([
        {"coin":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN-Custom", "orderbook_ticker":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1-Custom", "orderbook_ticker":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
    ]);
    let mut mm_bob = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(bob_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "i_am_seed": true,
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_bob_dump_log, _bob_dump_dashboard) = mm_dump(&mm_bob.log_path);

    let mut mm_alice = MarketMakerIt::start(
        json! ({
            "gui": "nogui",
            "netid": 9000,
            "dht": "on",  // Enable DHT without delay.
            "passphrase": format!("0x{}", hex::encode(alice_priv_key)),
            "coins": coins,
            "rpc_password": "pass",
            "seednodes": vec![format!("{}", mm_bob.ip)],
        }),
        "pass".to_string(),
        None,
    )
    .unwrap();
    let (_alice_dump_log, _alice_dump_dashboard) = mm_dump(&mm_alice.log_path);

    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_bob, "MYCOIN1-Custom", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN-Custom", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_alice, "MYCOIN1", &[], None)));
    let rc = block_on(mm_bob.rpc(&json! ({
        "userpass": mm_bob.userpass,
        "method": "setprice",
        "base": "MYCOIN",
        "rel": "MYCOIN1-Custom",
        "price": 1,
        "max": true,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let set_price: SetPriceResponse = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(set_price.result.base, "MYCOIN");
    assert_eq!(set_price.result.rel, "MYCOIN1-Custom");
    assert!(set_price.result.base_orderbook_ticker.is_none());
    assert_eq!(set_price.result.rel_orderbook_ticker, Some("MYCOIN1".to_owned()));

    // check orderbooks on bob side
    check_asks_num(&mm_bob, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_bob, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_bob, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_bob, "MYCOIN1", "MYCOIN", 1);

    // check multiple RPCs on alice side
    check_best_orders(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_volume(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "sell", "MYCOIN1-Custom", "MYCOIN", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN", "MYCOIN1", 1);
    check_best_orders_v2_by_number(&mm_alice, "buy", "MYCOIN-Custom", "MYCOIN1", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    check_asks_num(&mm_alice, "MYCOIN-Custom", "MYCOIN1-Custom", 1);
    check_asks_num(&mm_alice, "MYCOIN", "MYCOIN1", 1);
    check_bids_num(&mm_alice, "MYCOIN1-Custom", "MYCOIN-Custom", 1);
    check_bids_num(&mm_alice, "MYCOIN1", "MYCOIN", 1);

    check_orderbook_depth(
        &mm_alice,
        &[
            ("MYCOIN", "MYCOIN1"),
            ("MYCOIN", "MYCOIN1-Custom"),
            ("MYCOIN-Custom", "MYCOIN1"),
            ("MYCOIN-Custom", "MYCOIN1-Custom"),
        ],
        &[(1, 0); 4],
    );

    let rc = block_on(mm_alice.rpc(&json! ({
        "userpass": mm_alice.userpass,
        "method": "buy",
        "base": "MYCOIN-Custom",
        "rel": "MYCOIN1",
        "price": 1,
        "volume": "999.99999",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!buy: {}", rc.1);
    let buy_result: BuyOrSellRpcResult = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(buy_result.result.base, "MYCOIN-Custom");
    assert_eq!(buy_result.result.rel, "MYCOIN1");
    assert_eq!(buy_result.result.base_orderbook_ticker, Some("MYCOIN".to_owned()));
    assert!(buy_result.result.rel_orderbook_ticker.is_none());

    block_on(mm_bob.wait_for_log(22., |log| {
        log.contains("Entering the maker_swap_loop MYCOIN/MYCOIN1-Custom")
    }))
    .unwrap();
    block_on(mm_alice.wait_for_log(22., |log| {
        log.contains("Entering the taker_swap_loop MYCOIN-Custom/MYCOIN1")
    }))
    .unwrap();

    block_on(mm_bob.stop()).unwrap();
    block_on(mm_alice.stop()).unwrap();
}

// https://github.com/KomodoPlatform/atomicDEX-API/issues/1148
#[test]
fn test_zombie_order_after_balance_reduce_and_mm_restart() {
    let coins = json! ([
        {"coin":"MYCOIN", "asset":"MYCOIN","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
        {"coin":"MYCOIN1", "asset":"MYCOIN1","txversion":4,"overwintered":1,"txfee":1000,"protocol":{"type":"UTXO"}},
    ]);

    let seed_conf = json! ({
        "gui": "nogui",
        "netid": 9000,
        "dht": "on",  // Enable DHT without delay.
        "passphrase": "seednode",
        "coins": coins,
        "rpc_password": "pass",
        "i_am_seed": true,
    });
    let mm_seed = MarketMakerIt::start(seed_conf, "pass".to_string(), None).unwrap();

    let (_ctx, _, priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000.into());
    let mut conf = json! ({
        "gui": "nogui",
        "netid": 9000,
        "dht": "on",  // Enable DHT without delay.
        "passphrase": format!("0x{}", hex::encode(priv_key)),
        "coins": coins,
        "rpc_password": "pass",
        "i_am_seed": false,
        "seednodes": [mm_seed.ip],
    });

    let mm_maker = MarketMakerIt::start(conf.clone(), "pass".to_string(), None).unwrap();
    let (_dump_log, _dump_dashboard) = mm_dump(&mm_maker.log_path);

    log!("{:?}", block_on(enable_native(&mm_maker, "MYCOIN", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_maker, "MYCOIN1", &[], None)));

    let rc = block_on(mm_maker.rpc(&json! ({
        "userpass": mm_maker.userpass,
        "method": "setprice",
        "base": "MYCOIN",
        "rel": "MYCOIN1",
        "price": 1,
        "max": true,
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!setprice: {}", rc.1);
    let set_price_res: SetPriceResponse = serde_json::from_str(&rc.1).unwrap();

    println!("set_price_res {:?}", set_price_res);

    let withdraw = block_on(mm_maker.rpc(&json! ({
        "userpass": mm_maker.userpass,
        "method": "withdraw",
        "coin": "MYCOIN",
        "amount": "500",
        "to": "R9imXLs1hEcU9KbFDQq2hJEEJ1P5UoekaF",
    })))
    .unwrap();
    assert!(withdraw.0.is_success(), "!withdraw: {}", withdraw.1);

    let withdraw: Json = serde_json::from_str(&withdraw.1).unwrap();

    let send_raw = block_on(mm_maker.rpc(&json! ({
        "userpass": mm_maker.userpass,
        "method": "send_raw_transaction",
        "coin": "MYCOIN",
        "tx_hex": withdraw["tx_hex"],
    })))
    .unwrap();
    assert!(send_raw.0.is_success(), "!send_raw: {}", send_raw.1);

    let new_expected_vol: BigDecimal = "499.99998".parse().unwrap();

    thread::sleep(Duration::from_secs(32));

    log!("Get MYCOIN/MYCOIN1 orderbook");
    let rc = block_on(mm_maker.rpc(&json! ({
        "userpass": mm_maker.userpass,
        "method": "orderbook",
        "base": "MYCOIN",
        "rel": "MYCOIN1",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let orderbook: OrderbookResponse = serde_json::from_str(&rc.1).unwrap();
    log!("orderbook {:?}", orderbook);
    assert_eq!(
        orderbook.asks.len(),
        1,
        "MYCOIN/MYCOIN1 orderbook must have exactly 1 asks"
    );
    assert_eq!(orderbook.asks[0].entry.max_volume, new_expected_vol);

    log!("Get my orders");
    let rc = block_on(mm_maker.rpc(&json! ({
        "userpass": mm_maker.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
    let my_orders: MyOrdersRpcResult = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(my_orders.result.maker_orders.len(), 1);

    let my_order = my_orders.result.maker_orders.get(&set_price_res.result.uuid).unwrap();
    assert_eq!(my_order.max_base_vol, new_expected_vol);

    conf["dbdir"] = mm_maker.folder.join("DB").to_str().unwrap().into();
    conf["log"] = mm_maker.folder.join("mm2_dup.log").to_str().unwrap().into();
    block_on(mm_maker.stop()).unwrap();

    let mm_maker_dup = MarketMakerIt::start(conf.clone(), "pass".to_string(), None).unwrap();
    let (_dup_dump_log, _dup_dump_dashboard) = mm_dump(&mm_maker_dup.log_path);

    // we should ignore our state submitted by another node to us
    log!("Get MYCOIN/MYCOIN1 orderbook");
    let rc = block_on(mm_maker_dup.rpc(&json! ({
        "userpass": mm_maker_dup.userpass,
        "method": "orderbook",
        "base": "MYCOIN",
        "rel": "MYCOIN1",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let orderbook: OrderbookResponse = serde_json::from_str(&rc.1).unwrap();
    log!("orderbook {:?}", orderbook);
    assert!(
        orderbook.asks.is_empty(),
        "MYCOIN/MYCOIN1 orderbook must have empty asks"
    );

    // activate coins to kickstart our order
    log!("{:?}", block_on(enable_native(&mm_maker_dup, "MYCOIN", &[], None)));
    log!("{:?}", block_on(enable_native(&mm_maker_dup, "MYCOIN1", &[], None)));

    thread::sleep(Duration::from_secs(5));

    log!("Get MYCOIN/MYCOIN1 orderbook");
    let rc = block_on(mm_maker_dup.rpc(&json! ({
        "userpass": mm_maker_dup.userpass,
        "method": "orderbook",
        "base": "MYCOIN",
        "rel": "MYCOIN1",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

    let orderbook: OrderbookResponse = serde_json::from_str(&rc.1).unwrap();
    log!("orderbook {:?}", orderbook);
    assert_eq!(
        orderbook.asks.len(),
        1,
        "MYCOIN/MYCOIN1 orderbook must have exactly 1 asks"
    );
    assert_eq!(orderbook.asks[0].entry.max_volume, new_expected_vol);

    log!("Get my orders");
    let rc = block_on(mm_maker_dup.rpc(&json! ({
        "userpass": mm_maker_dup.userpass,
        "method": "my_orders",
    })))
    .unwrap();
    assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
    let my_orders: MyOrdersRpcResult = serde_json::from_str(&rc.1).unwrap();
    assert_eq!(my_orders.result.maker_orders.len(), 1);

    let my_order = my_orders.result.maker_orders.get(&set_price_res.result.uuid).unwrap();
    assert_eq!(my_order.max_base_vol, new_expected_vol);
}
