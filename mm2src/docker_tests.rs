#![feature(custom_test_frameworks)]
#![feature(test)]
#![test_runner(docker_tests_runner)]
#![feature(drain_filter)]
#![feature(non_ascii_idents)]

#[cfg(test)] use docker_tests::docker_tests_runner;
#[cfg(test)] #[macro_use] extern crate common;
#[cfg(test)] #[macro_use] extern crate fomat_macros;
#[cfg(test)] #[macro_use] extern crate gstuff;
#[cfg(test)] #[macro_use] extern crate lazy_static;
#[cfg(test)] #[macro_use] extern crate serde_json;
#[cfg(test)] #[macro_use] extern crate serde_derive;
#[cfg(test)] #[macro_use] extern crate serialization_derive;
#[cfg(test)] extern crate test;
#[cfg(test)] #[macro_use] extern crate unwrap;

#[cfg(test)]
#[path = "mm2.rs"]
pub mod mm2;

fn main() {
    unimplemented!()
}

#[cfg(all(test, feature = "native"))]
mod docker_tests {
    use common::{block_on, new_uuid};
    use common::crypto::{CryptoOps, SecretHash, SecretHashAlgo};
    use common::for_tests::{enable_native, MarketMakerIt, mm_dump};
    use coins::{FoundSwapTxSpend, MarketCoinOps, MmCoin, SwapOps, Transaction, WithdrawRequest};
    use coins::utxo::{coin_daemon_data_dir, dhash160, utxo_coin_from_conf_and_request, zcash_params_path, UtxoCoin};
    use coins::utxo::rpc_clients::{UtxoRpcClientEnum, UtxoRpcClientOps};
    use coins::tezos::{mla_mint_call, prepare_tezos_sandbox_network, tezos_coin_for_test, tezos_mla_coin_for_test, TezosCoin, TezosAddress};
    use coins::tezos::tezos_constants::*;
    use futures01::Future;
    use gstuff::now_ms;
    use super::mm2::mm2_tests::trade_between_2_nodes;
    use secp256k1::SecretKey;
    use serde_json::{self as json, Value as Json};
    use std::env;
    use std::io::{BufRead, BufReader};
    use std::process::Command;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use test::{list_tests_console, Options, parse_opts, run_tests_console, StaticTestFn, StaticBenchFn, TestDescAndFn};
    use testcontainers::{Container, Docker, Image};
    use testcontainers::clients::Cli;
    use testcontainers::images::generic::{GenericImage, WaitFor};

    // The copy of libtest function returning the exit code instead of immediate process exit
    fn test_main(args: &[String], tests: Vec<TestDescAndFn>, options: Options) -> i32 {
        let mut opts = match parse_opts(args) {
            Some(Ok(o)) => o,
            Some(Err(msg)) => {
                eprintln!("error: {}", msg);
                return 101
            },
            None => return 0,
        };

        opts.options = options;
        if opts.list {
            if let Err(e) = list_tests_console(&opts, tests) {
                eprintln!("error: io error when listing tests: {:?}", e);
                return 101;
            }
            0
        } else {
            match run_tests_console(&opts, tests) {
                Ok(true) => 0,
                Ok(false) => 101,
                Err(e) => {
                    eprintln!("error: io error when listing tests: {:?}", e);
                    101
                }
            }
        }
    }

    fn kill_containers_by_image(img: &str) {
        let stdout = Command::new("docker")
            .arg("ps")
            .arg("-f")
            .arg(fomat!("ancestor=" (img)))
            .arg("-q")
            .output()
            .expect("Failed to execute docker command");

        let reader = BufReader::new(stdout.stdout.as_slice());
        let ids: Vec<_> = reader.lines().map(|line| line.unwrap()).collect();
        if !ids.is_empty() {
            Command::new("docker")
                .arg("rm")
                .arg("-f")
                .args(ids)
                .status()
                .expect("Failed to execute docker command");
        }
    }

    // AP: custom test runner is intended to initialize the required environment (e.g. coin daemons in the docker containers)
    // and then gracefully clear it by dropping the RAII docker container handlers
    // I've tried to use static for such singleton initialization but it turned out that despite
    // rustc allows to use Drop as static the drop fn won't ever be called
    // NB: https://github.com/rust-lang/rfcs/issues/1111
    // the only preparation step required is Zcash params files downloading:
    // Windows - https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.bat
    // Linux and MacOS - https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.sh
    pub fn docker_tests_runner(tests: &[&TestDescAndFn]) {
        // pretty_env_logger::try_init();
        let docker = Cli::default();
        let mut containers = vec![];
        // skip Docker containers initialization if we are intended to run test_mm_start only
        if std::env::var("_MM2_TEST_CONF").is_err() {
            Command::new("docker").arg("pull").arg("artempikulin/testblockchain")
                .status().expect("Failed to execute docker command");

            Command::new("docker").arg("pull").arg("artempikulin/tezos-sandbox")
                .status().expect("Failed to execute docker command");

            kill_containers_by_image("artempikulin/testblockchain");
            kill_containers_by_image("artempikulin/tezos-sandbox");

            let utxo_node = utxo_docker_node(&docker, "MYCOIN", 7000);
            let utxo_node1 = utxo_docker_node(&docker, "MYCOIN1", 8000);
            utxo_node.wait_ready();
            utxo_node1.wait_ready();
            containers.push(utxo_node);
            containers.push(utxo_node1);

            let tezos_node = tezos_docker_node(&docker, "XTZ", 20000);
            let xtz_contracts = prepare_tezos_sandbox_network();
            *unwrap!(XTZ_SWAP_CONTRACT.lock()) = xtz_contracts.0;
            *unwrap!(XTZ_MLA_CONTRACT.lock()) = xtz_contracts.1;
            containers.push(tezos_node);
        }
        // detect if docker is installed
        // skip the tests that use docker if not installed
        let owned_tests: Vec<_> = tests
            .iter()
            .map(|t| match t.testfn {
                StaticTestFn(f) => TestDescAndFn {
                    testfn: StaticTestFn(f),
                    desc: t.desc.clone(),
                },
                StaticBenchFn(f) => TestDescAndFn {
                    testfn: StaticBenchFn(f),
                    desc: t.desc.clone(),
                },
                _ => panic!("non-static tests passed to lp_coins test runner"),
            })
            .collect();
        let args: Vec<String> = std::env::args().collect();
        let exit_code = test_main(&args, owned_tests, Options::new());
        // drop explicitly as process::exit breaks standard Rust lifecycle
        drop(containers);
        std::process::exit(exit_code);
    }

    struct UtxoDockerNode<'a> {
        container: Container<'a, Cli, GenericImage>,
        ticker: String,
        port: u16,
    }

    impl<'a> UtxoDockerNode<'a> {
        pub fn wait_ready(&self) {
            let conf = json!({"asset":self.ticker});
            let req = json!({"method":"enable"});
            let priv_key = unwrap!(hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f"));
            let coin = unwrap!(block_on(utxo_coin_from_conf_and_request(&self.ticker, &conf, &req, &priv_key)));
            let timeout = now_ms() + 30000;
            loop {
                match coin.rpc_client().get_block_count().wait() {
                    Ok(n) => if n > 1 { break },
                    Err(e) => log!([e]),
                }
                assert!(now_ms() < timeout, "Test timed out");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    fn utxo_docker_node<'a>(docker: &'a Cli, ticker: &'static str, port: u16) -> UtxoDockerNode<'a> {
        let args = vec![
            "-v".into(), format!("{}:/data/.zcash-params", zcash_params_path().display()),
            "-p".into(), format!("127.0.0.1:{}:{}", port, port).into()
        ];
        let image = GenericImage::new("artempikulin/testblockchain")
            .with_args(args)
            .with_env_var("CLIENTS", "2")
            .with_env_var("CHAIN", ticker)
            .with_env_var("TEST_ADDY", "R9imXLs1hEcU9KbFDQq2hJEEJ1P5UoekaF")
            .with_env_var("TEST_WIF", "UqqW7f766rADem9heD8vSBvvrdfJb3zg5r8du9rJxPtccjWf7RG9")
            .with_env_var("TEST_PUBKEY", "021607076d7a2cb148d542fb9644c04ffc22d2cca752f80755a0402a24c567b17a")
            .with_env_var("DAEMON_URL", "http://test:test@127.0.0.1:7000")
            .with_env_var("COIN", "Komodo")
            .with_env_var("COIN_RPC_PORT", port.to_string())
            .with_wait_for(WaitFor::message_on_stdout("config is ready"));
        let container = docker.run(image);
        let mut conf_path = coin_daemon_data_dir(ticker, true);
        unwrap!(std::fs::create_dir_all(&conf_path));
        conf_path.push(format!("{}.conf", ticker));
        Command::new("docker")
            .arg("cp")
            .arg(format!("{}:/data/node_0/{}.conf", container.id(), ticker))
            .arg(&conf_path)
            .status()
            .expect("Failed to execute docker command");
        let timeout = now_ms() + 3000;
        loop {
            if conf_path.exists() { break };
            assert!(now_ms() < timeout, "Test timed out");
        }
        UtxoDockerNode {
            container,
            ticker: ticker.into(),
            port,
        }
    }

    fn tezos_docker_node<'a>(docker: &'a Cli, ticker: &'static str, port: u16) -> UtxoDockerNode<'a> {
        let args = vec![
            "-p".into(), "127.0.0.1:20000:20000".into(),
            "-it".into()
        ];
        let image = GenericImage::new("artempikulin/tezos-sandbox")
            .with_args(args)
            .with_wait_for(WaitFor::message_on_stdout("Sandbox is READY"));
        let container = docker.run(image);
        UtxoDockerNode {
            container,
            ticker: ticker.into(),
            port,
        }
    }

    lazy_static! {
        static ref COINS_LOCK: Mutex<()> = Mutex::new(());
        static ref XTZ_SWAP_CONTRACT: Mutex<String> = Mutex::new(String::new());
        // Manager ledger asset contract
        static ref XTZ_MLA_CONTRACT: Mutex<String> = Mutex::new(String::new());
    }

    // generate random privkey, create a coin and fill it's address with 1000 coins
    fn generate_utxo_coin_with_random_privkey(ticker: &str, balance: u64) -> (UtxoCoin, [u8; 32])  {
        // prevent concurrent initialization since daemon RPC returns errors if send_to_address
        // is called concurrently (insufficient funds) and it also may return other errors
        // if previous transaction is not confirmed yet
        let _lock = unwrap!(COINS_LOCK.lock());
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let conf = json!({"asset":ticker,"txversion":4,"overwintered":1});
        let req = json!({"method":"enable"});
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = unwrap!(block_on(utxo_coin_from_conf_and_request(ticker, &conf, &req, &priv_key)));
        fill_utxo_address(&coin, &coin.my_address(), balance, timeout);
        (coin, priv_key)
    }

    fn fill_utxo_address(coin: &UtxoCoin, address: &str, amount: u64, timeout: u64) {
        if let UtxoRpcClientEnum::Native(client) = &coin.rpc_client() {
            unwrap!(client.import_address(&coin.my_address(), &coin.my_address(), false).wait());
            let hash = client.send_to_address(address, &amount.into()).wait().unwrap();
            let tx_bytes = client.get_transaction_bytes(hash).wait().unwrap();
            unwrap!(coin.wait_for_confirmations(&tx_bytes, 1, timeout, 1, 0).wait());
            log!({ "{:02x}", tx_bytes });
            loop {
                let unspents = client.list_unspent(0, std::i32::MAX, vec![coin.my_address().into()]).wait().unwrap();
                log!([unspents]);
                if !unspents.is_empty() {
                    break;
                }
                assert!(now_ms() / 1000 < timeout, "Test timed out");
                thread::sleep(Duration::from_secs(1));
            };
        };
    }

    fn fill_xtz_address(address: &TezosAddress) {
        // edsk3RFgDiCt7tWB4bSUSXJgA5EQeXomgnMjF9fnDkeN96zsYxtbPC in hex
        let priv_key = unwrap!(hex::decode("626f6f746163632d33626f6f746163632d33626f6f746163632d33626f6f7461"));
        let coin = tezos_coin_for_test(&priv_key, "http://localhost:20000", &unwrap!(XTZ_SWAP_CONTRACT.lock()));
        let op = unwrap!(block_on(coin.sign_and_send_operation(
            100000000u64.into(),
            address,
            None,
        )));
        unwrap!(coin.wait_for_confirmations(
            &op.tx_hex(),
            1,
            now_ms() / 1000 + 120,
            1,
            1,
        ).wait());

        let params = mla_mint_call(&address, &100000000u64.into());
        let operation = unwrap!(block_on(coin.sign_and_send_operation(
            0u8.into(),
            &unwrap!(unwrap!(XTZ_MLA_CONTRACT.lock()).parse()),
            Some(params),
        )));
        unwrap!(coin.wait_for_confirmations(
            &operation.tx_hex(),
            1,
            now_ms() / 1000 + 120,
            1,
            1,
        ).wait());
    }

    #[test]
    fn test_search_for_swap_tx_spend_native_was_refunded() {
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let (coin, _) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000);

        let time_lock = (now_ms() / 1000) as u32 - 3600;
        let tx = coin.send_taker_payment(
            &[],
            time_lock,
            &coin.get_pubkey(),
            &SecretHash::default(),
            1.into(),
        ).wait().unwrap();

        unwrap!(coin.wait_for_confirmations(&tx.tx_hex, 1, timeout, 1, 0).wait());

        let refund_tx = coin.send_taker_refunds_payment(
            &[],
            &tx.tx_hex,
            time_lock,
            &coin.get_pubkey(),
            &SecretHash::default(),
        ).wait().unwrap();

        unwrap!(coin.wait_for_confirmations(&refund_tx.tx_hex(), 1, timeout, 1, 0).wait());

        let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            time_lock,
            &coin.get_pubkey(),
            &SecretHash::default(),
            &tx.tx_hex,
            0,
        ).wait()));
        assert_eq!(FoundSwapTxSpend::Refunded(refund_tx), found);
    }

    #[test]
    fn test_search_for_swap_tx_spend_native_was_spent() {
        let timeout = (now_ms() / 1000) + 120; // timeout if test takes more than 120 seconds to run
        let (coin, _) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000);
        let secret = [0; 32];
        let secret_hash = SecretHash::from_secret(SecretHashAlgo::Ripe160Sha256, &secret);

        let time_lock = (now_ms() / 1000) as u32 - 3600;
        let tx = coin.send_taker_payment(
            &[],
            time_lock,
            &coin.get_pubkey(),
            &secret_hash,
            1.into(),
        ).wait().unwrap();

        unwrap!(coin.wait_for_confirmations(&tx.tx_hex, 1, timeout, 1, 0).wait());

        let spend_tx = coin.send_maker_spends_taker_payment(
            &[],
            &tx.tx_hex,
            time_lock,
            &coin.get_pubkey(),
            &secret,
            &secret_hash,
        ).wait().unwrap();

        unwrap!(coin.wait_for_confirmations(&spend_tx.tx_hex(), 1, timeout, 1, 0).wait());

        let found = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            time_lock,
            &coin.get_pubkey(),
            &secret_hash,
            &tx.tx_hex,
            0,
        ).wait()));
        assert_eq!(FoundSwapTxSpend::Spent(spend_tx), found);
    }

    // https://github.com/KomodoPlatform/atomicDEX-API/issues/554
    #[test]
    fn order_should_be_cancelled_when_entire_balance_is_withdrawn() {
        let (_, priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1},
        ]);
        let mut mm_bob = unwrap! (MarketMakerIt::start (
            json! ({
                "gui": "nogui",
                "netid": 9000,
                "dht": "on",  // Enable DHT without delay.
                "myipaddr": env::var ("BOB_TRADE_IP") .ok(),
                "rpcip": env::var ("BOB_TRADE_IP") .ok(),
                "canbind": env::var ("BOB_TRADE_PORT") .ok().map (|s| unwrap! (s.parse::<i64>())),
                "passphrase": format!("0x{}", hex::encode(priv_key)),
                "coins": coins,
                "rpc_password": "pass",
                "i_am_seed": true,
            }),
            "pass".to_string(),
            None,
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump (&mm_bob.log_path);
        unwrap! (block_on (mm_bob.wait_for_log (60., |log| log.contains (">>>>>>>>> DEX stats "))));
        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![], ""))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![], ""))]);
        let rc = unwrap! (block_on (mm_bob.rpc (json! ({
            "userpass": mm_bob.userpass,
            "method": "setprice",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
            "price": 1,
            "volume": "999",
        }))));
        assert! (rc.0.is_success(), "!setprice: {}", rc.1);

        thread::sleep(Duration::from_secs(12));

        log!("Get MYCOIN/MYCOIN1 orderbook");
        let rc = unwrap! (block_on (mm_bob.rpc (json! ({
            "userpass": mm_bob.userpass,
            "method": "orderbook",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
        }))));
        assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

        let bob_orderbook: Json = unwrap!(json::from_str(&rc.1));
        log!("orderbook " [bob_orderbook]);
        let asks = bob_orderbook["asks"].as_array().unwrap();
        assert_eq!(asks.len(), 1, "MYCOIN/MYCOIN1 orderbook must have exactly 1 ask");

        let withdraw = unwrap! (block_on (mm_bob.rpc (json! ({
            "userpass": mm_bob.userpass,
            "method": "withdraw",
            "coin": "MYCOIN",
            "max": true,
            "to": "R9imXLs1hEcU9KbFDQq2hJEEJ1P5UoekaF",
        }))));
        assert!(withdraw.0.is_success(), "!withdraw: {}", withdraw.1);

        let withdraw: Json = unwrap!(json::from_str(&withdraw.1));

        let send_raw = unwrap! (block_on (mm_bob.rpc (json! ({
            "userpass": mm_bob.userpass,
            "method": "send_raw_transaction",
            "coin": "MYCOIN",
            "tx_hex": withdraw["tx_hex"],
        }))));
        assert!(send_raw.0.is_success(), "!send_raw: {}", send_raw.1);

        thread::sleep(Duration::from_secs(12));

        log!("Get MYCOIN/MYCOIN1 orderbook");
        let rc = unwrap! (block_on (mm_bob.rpc (json! ({
            "userpass": mm_bob.userpass,
            "method": "orderbook",
            "base": "MYCOIN",
            "rel": "MYCOIN1",
        }))));
        assert!(rc.0.is_success(), "!orderbook: {}", rc.1);

        let bob_orderbook: Json = unwrap!(json::from_str(&rc.1));
        log!("orderbook " (unwrap!(json::to_string(&bob_orderbook))));
        let asks = bob_orderbook["asks"].as_array().unwrap();
        assert_eq!(asks.len(), 0, "MYCOIN/MYCOIN1 orderbook must have exactly 0 asks");

        log!("Get my orders");
        let rc = unwrap! (block_on (mm_bob.rpc (json! ({
            "userpass": mm_bob.userpass,
            "method": "my_orders",
        }))));
        assert!(rc.0.is_success(), "!my_orders: {}", rc.1);
        let orders: Json = unwrap!(json::from_str(&rc.1));
        log!("my_orders " (unwrap!(json::to_string(&orders))));
        assert!(unwrap!(orders["result"]["maker_orders"].as_object()).is_empty(), "maker_orders must be empty");

        unwrap!(block_on(mm_bob.stop()));
    }

    // https://github.com/KomodoPlatform/atomicDEX-API/issues/471
    #[test]
    fn match_and_trade_max() {
        let (_, bob_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN", 1000);
        let (_, alice_priv_key) = generate_utxo_coin_with_random_privkey("MYCOIN1", 3000);
        let coins = json! ([
            {"coin":"MYCOIN","asset":"MYCOIN","txversion":4,"overwintered":1},
            {"coin":"MYCOIN1","asset":"MYCOIN1","txversion":4,"overwintered":1},
        ]);
        let mut mm_bob = unwrap! (MarketMakerIt::start (
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
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump (&mm_bob.log_path);
        log! ({"Bob log path: {}", mm_bob.log_path.display()});

        unwrap! (block_on (mm_bob.wait_for_log (22., |log| log.contains (">>>>>>>>> DEX stats "))));

        let mut mm_alice = unwrap! (MarketMakerIt::start (
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
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump (&mm_alice.log_path);
        log! ({"Alice log path: {}", mm_alice.log_path.display()});

        unwrap! (block_on (mm_alice.wait_for_log (22., |log| log.contains (">>>>>>>>> DEX stats "))));

        log!([block_on(enable_native(&mm_bob, "MYCOIN", vec![], ""))]);
        log!([block_on(enable_native(&mm_bob, "MYCOIN1", vec![], ""))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN", vec![], ""))]);
        log!([block_on(enable_native(&mm_alice, "MYCOIN1", vec![], ""))]);
        block_on(trade_between_2_nodes(&mut mm_bob, &mut mm_alice, vec![("MYCOIN", "MYCOIN1")], "999.9999", true));
    }

    #[test]
    fn send_and_spend_xtz_payment() {
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = tezos_coin_for_test(&priv_key, "http://localhost:20000", &unwrap!(XTZ_SWAP_CONTRACT.lock()));
        fill_xtz_address(&coin.my_address);
        let uuid = new_uuid();
        let secret = [0; 32];
        let secret_hash = SecretHash::from_secret(SecretHashAlgo::Sha256, &secret);

        let payment = unwrap!(coin.send_taker_payment(
            uuid.as_bytes(),
            0,
            &coin.get_pubkey(),
            &secret_hash,
            1.into(),
        ).wait());
        unwrap!(coin.wait_for_confirmations(
            &payment.tx_hex,
            1,
            now_ms() / 1000 + 120,
            1,
            1
        ).wait());

        let spend = unwrap!(coin.send_maker_spends_taker_payment(
            uuid.as_bytes(),
            &payment.tx_hex,
            0,
            &coin.get_pubkey(),
            &secret,
            &secret_hash,
        ).wait());
        unwrap!(coin.wait_for_confirmations(
            &spend.tx_hex(),
            1,
            now_ms() / 1000 + 120,
            1,
            1
        ).wait());

        let find = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            0,
            &coin.get_pubkey(),
            &secret_hash,
            &payment.tx_hex,
            1,
        ).wait()));
        assert_eq!(FoundSwapTxSpend::Spent(spend), find);
    }

    #[test]
    fn send_and_refund_xtz_payment() {
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = tezos_coin_for_test(&priv_key, "http://localhost:20000", &unwrap!(XTZ_SWAP_CONTRACT.lock()));
        fill_xtz_address(&coin.my_address);
        let uuid = new_uuid();
        let secret = [0; 32];
        let secret_hash = SecretHash::from_secret(SecretHashAlgo::Sha256, &secret);

        let payment = unwrap!(coin.send_taker_payment(
            uuid.as_bytes(),
            0,
            &coin.get_pubkey(),
            &secret_hash,
            1.into(),
        ).wait());
        unwrap!(coin.wait_for_confirmations(
            &payment.tx_hex,
            1,
            now_ms() / 1000 + 120,
            1,
            1
        ).wait());

        let refund = unwrap!(coin.send_taker_refunds_payment(
            uuid.as_bytes(),
            &payment.tx_hex,
            0,
            &coin.get_pubkey(),
            &secret_hash,
        ).wait());
        unwrap!(coin.wait_for_confirmations(
            &refund.tx_hex(),
            1,
            now_ms() / 1000 + 120,
            1,
            1
        ).wait());

        let find = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            0,
            &coin.get_pubkey(),
            &secret_hash,
            &payment.tx_hex,
            1,
        ).wait()));
        assert_eq!(FoundSwapTxSpend::Refunded(refund), find);
    }

    #[test]
    fn withdraw_managed_ledger_asset() {
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = tezos_mla_coin_for_test(
            &priv_key,
            "http://localhost:20000",
            &unwrap!(XTZ_SWAP_CONTRACT.lock()),
            &unwrap!(XTZ_MLA_CONTRACT.lock()),
        );
        fill_xtz_address(&coin.my_address);

        let req_str = r#"{"coin":"XTZ_MLA","to":"KT1BhA5bCx37GjwrVy2egw7NKpir1bUt7nKj","amount":"20"}"#;
        let req: WithdrawRequest = unwrap!(json::from_str(req_str));
        let withdraw = unwrap!(coin.withdraw(req).wait());
        let tx = unwrap!(coin.send_raw_tx(&hex::encode(&withdraw.tx_hex.0)).wait());
        unwrap!(coin.wait_for_confirmations(
            &withdraw.tx_hex.0,
            1,
            now_ms() / 1000 + 120,
            1,
            1,
        ).wait());
        let balance = coin.my_balance().wait().unwrap();
        assert_eq!(balance, 80.into());
    }

    #[test]
    fn send_and_refund_managed_ledger_asset_payment() {
        let priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let coin = tezos_mla_coin_for_test(
            &priv_key,
            "http://localhost:20000",
            &unwrap!(XTZ_SWAP_CONTRACT.lock()),
            &unwrap!(XTZ_MLA_CONTRACT.lock()),
        );
        fill_xtz_address(&coin.my_address);
        let params = mla_mint_call(&coin.my_address, &100000000u64.into());
        let operation = unwrap!(block_on(coin.sign_and_send_operation(
            0u8.into(),
            &unwrap!(unwrap!(XTZ_MLA_CONTRACT.lock()).parse()),
            Some(params),
        )));
        unwrap!(coin.wait_for_confirmations(
            &operation.tx_hex(),
            1,
            now_ms() / 1000 + 120,
            1,
            1,
        ).wait());

        let uuid = new_uuid();
        let secret = [0; 32];
        let secret_hash = SecretHash::from_secret(SecretHashAlgo::Sha256, &secret);
        let payment = unwrap!(coin.send_taker_payment(
            uuid.as_bytes(),
            0,
            &coin.get_pubkey(),
            &secret_hash,
            1.into(),
        ).wait());
        unwrap!(coin.wait_for_confirmations(
            &payment.tx_hex,
            1,
            now_ms() / 1000 + 120,
            1,
            1
        ).wait());
        let balance = coin.my_balance().wait().unwrap();
        assert_eq!(balance, 99.into());

        let refund = unwrap!(coin.send_taker_refunds_payment(
            uuid.as_bytes(),
            &payment.tx_hex,
            0,
            &coin.get_pubkey(),
            &secret_hash,
        ).wait());
        unwrap!(coin.wait_for_confirmations(
            &refund.tx_hex(),
            1,
            now_ms() / 1000 + 120,
            1,
            1
        ).wait());

        let balance = coin.my_balance().wait().unwrap();
        assert_eq!(balance, 100.into());

        let find = unwrap!(unwrap!(coin.search_for_swap_tx_spend_my(
            0,
            &coin.get_pubkey(),
            &secret_hash,
            &payment.tx_hex,
            1,
        ).wait()));

        assert_eq!(FoundSwapTxSpend::Refunded(refund), find);
    }

    #[test]
    fn test_trade_xtz_mla() {
        let bob_priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let bob_coin = tezos_coin_for_test(
            &bob_priv_key,
            "http://localhost:20000",
            &unwrap!(XTZ_SWAP_CONTRACT.lock()),
        );
        fill_xtz_address(&bob_coin.my_address);
        let alice_priv_key = SecretKey::random(&mut rand4::thread_rng()).serialize();
        let alice_coin = tezos_coin_for_test(
            &alice_priv_key,
            "http://localhost:20000",
            &unwrap!(XTZ_SWAP_CONTRACT.lock()),
        );
        fill_xtz_address(&alice_coin.my_address);

        let coins = json! ([
            {"coin":"XTZ","name":"tezosbabylonnet","ed25519_addr_prefix":[6, 161, 159],"secp256k1_addr_prefix":[6, 161, 161],"p256_addr_prefix":[6, 161, 164],"protocol":{"platform":"TEZOS","token_type":"TEZOS"},"mm2":1},
            {
                "coin": "XTZ_MLA",
                "name": "tezos_managed_ledger_asset",
                "ed25519_addr_prefix": TZ1_ADDR_PREFIX,
                "secp256k1_addr_prefix": TZ2_ADDR_PREFIX,
                "p256_addr_prefix": TZ3_ADDR_PREFIX,
                "protocol": {
                    "platform": "TEZOS",
                    "token_type": "MLA",
                    "contract_address": *unwrap!(XTZ_MLA_CONTRACT.lock())
                },
                "mm2": 1
            },
        ]);
        let mut mm_bob = unwrap! (MarketMakerIt::start (
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
        ));
        let (_bob_dump_log, _bob_dump_dashboard) = mm_dump (&mm_bob.log_path);
        log! ({"Bob log path: {}", mm_bob.log_path.display()});

        unwrap! (block_on (mm_bob.wait_for_log (22., |log| log.contains (">>>>>>>>> DEX stats "))));

        let mut mm_alice = unwrap! (MarketMakerIt::start (
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
        ));
        let (_alice_dump_log, _alice_dump_dashboard) = mm_dump (&mm_alice.log_path);
        log! ({"Alice log path: {}", mm_alice.log_path.display()});

        unwrap! (block_on (mm_alice.wait_for_log (22., |log| log.contains (">>>>>>>>> DEX stats "))));

        log!([block_on(enable_native(&mm_bob, "XTZ", vec!["http://localhost:20000"], &unwrap!(XTZ_SWAP_CONTRACT.lock())))]);
        log!([block_on(enable_native(&mm_bob, "XTZ_MLA", vec!["http://localhost:20000"], &unwrap!(XTZ_SWAP_CONTRACT.lock())))]);
        log!([block_on(enable_native(&mm_alice, "XTZ", vec!["http://localhost:20000"], &unwrap!(XTZ_SWAP_CONTRACT.lock())))]);
        log!([block_on(enable_native(&mm_alice, "XTZ_MLA", vec!["http://localhost:20000"], &unwrap!(XTZ_SWAP_CONTRACT.lock())))]);
        block_on(trade_between_2_nodes(&mut mm_bob, &mut mm_alice, vec![("XTZ", "XTZ_MLA")], "1", true));
    }
}
