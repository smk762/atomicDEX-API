use common::block_on;
use common::crypto::{SecretHash, SecretHashType};
use common::mm_ctx::{MmArc, MmCtxBuilder};
use common::for_tests::wait_for_log;
use futures::future::join_all;
use super::*;
use mocktopus::mocking::*;

fn check_sum(addr: &str, expected: &str) {
    let actual = checksum_address(addr);
    assert_eq!(expected, actual);
}

fn eth_coin_for_test(coin_type: EthCoinType, urls: Vec<String>) -> (MmArc, EthCoin) {
    let secret_bytes = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = KeyPair::from_secret_slice(&secret_bytes).unwrap();
    let transport = Web3Transport::new(urls).unwrap();
    let web3 = Web3::new(transport);
    let ctx = MmCtxBuilder::new().into_mm_arc();

    let eth_coin = EthCoin(Arc::new(EthCoinImpl {
        coin_type,
        decimals: 18,
        gas_station_url: None,
        history_sync_state: Mutex::new(HistorySyncState::NotEnabled),
        my_address: key_pair.address(),
        priv_key: unwrap!(EcPrivkey::new(CurveType::SECP256K1, &secret_bytes)),
        swap_contract_address: Address::from("0x7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
        ticker: "ETH".into(),
        web3_instances: vec![Web3Instance {web3: web3.clone(), is_parity: true}],
        web3,
        ctx: ctx.weak(),
        required_confirmations: 1.into(),
    }));
    (ctx, eth_coin)
}

#[test]
/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md#test-cases
fn test_check_sum_address() {
    check_sum("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    check_sum("0x52908400098527886e0f7030069857d2e4169ee7", "0x52908400098527886E0F7030069857D2E4169EE7");
    check_sum("0x8617e340b3d01fa5f11f306f4090fd50e238070d", "0x8617E340B3D01FA5F11F306F4090FD50E238070D");
    check_sum("0xde709f2102306220921060314715629080e2fb77", "0xde709f2102306220921060314715629080e2fb77");
    check_sum("0x27b1fdb04752bbc536007a920d24acb045561c26", "0x27b1fdb04752bbc536007a920d24acb045561c26");
    check_sum("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    check_sum("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    check_sum("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB");
    check_sum("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb");
}

#[test]
fn test_is_valid_checksum_addr() {
    assert!(is_valid_checksum_addr("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"));
    assert!(is_valid_checksum_addr("0x52908400098527886E0F7030069857D2E4169EE7"));
    assert!(!is_valid_checksum_addr("0x8617e340B3D01FA5F11F306F4090FD50E238070D"));
    assert!(!is_valid_checksum_addr("0xd1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"));
}

#[test]
fn display_u256_with_point() {
    let number = U256::from_dec_str("1000000000000000000").unwrap();
    let string = display_u256_with_decimal_point(number, 18);
    assert_eq!("1.", string);

    let number = U256::from_dec_str("10000000000000000000000000000000000000000000000000000000000").unwrap();
    let string = display_u256_with_decimal_point(number, 18);
    assert_eq!("10000000000000000000000000000000000000000.", string);

    let number = U256::from_dec_str("1234567890000000000").unwrap();
    let string = display_u256_with_decimal_point(number, 18);
    assert_eq!("1.23456789", string);

    let number = U256::from_dec_str("1234567890000000000").unwrap();
    let string = display_u256_with_decimal_point(number, 16);
    assert_eq!("123.456789", string);

    let number = U256::from_dec_str("1234567890000000000").unwrap();
    let string = display_u256_with_decimal_point(number, 0);
    assert_eq!("1234567890000000000.", string);

    let number = U256::from_dec_str("1000000000000000").unwrap();
    let string = display_u256_with_decimal_point(number, 18);
    assert_eq!("0.001", string);

    let number = U256::from_dec_str("0").unwrap();
    let string = display_u256_with_decimal_point(number, 18);
    assert_eq!("0.", string);

    let number = U256::from_dec_str("0").unwrap();
    let string = display_u256_with_decimal_point(number, 0);
    assert_eq!("0.", string);
}

#[test]
fn test_wei_from_big_decimal() {
    let amount = "0.000001".parse().unwrap();
    let wei = wei_from_big_decimal(&amount, 18).unwrap();
    let expected_wei: U256 = 1000000000000u64.into();
    assert_eq!(expected_wei, wei);

    let amount = "1.000001".parse().unwrap();
    let wei = wei_from_big_decimal(&amount, 18).unwrap();
    let expected_wei: U256 = 1000001000000000000u64.into();
    assert_eq!(expected_wei, wei);

    let amount = 1.into();
    let wei = wei_from_big_decimal(&amount, 18).unwrap();
    let expected_wei: U256 = 1000000000000000000u64.into();
    assert_eq!(expected_wei, wei);

    let amount = "0.000000000000000001".parse().unwrap();
    let wei = wei_from_big_decimal(&amount, 18).unwrap();
    let expected_wei: U256 = 1u64.into();
    assert_eq!(expected_wei, wei);

    let amount = 1234.into();
    let wei = wei_from_big_decimal(&amount, 9).unwrap();
    let expected_wei: U256 = 1234000000000u64.into();
    assert_eq!(expected_wei, wei);

    let amount = 1234.into();
    let wei = wei_from_big_decimal(&amount, 0).unwrap();
    let expected_wei: U256 = 1234u64.into();
    assert_eq!(expected_wei, wei);

    let amount = 1234.into();
    let wei = wei_from_big_decimal(&amount, 1).unwrap();
    let expected_wei: U256 = 12340u64.into();
    assert_eq!(expected_wei, wei);

    let amount = "1234.12345".parse().unwrap();
    let wei = wei_from_big_decimal(&amount, 1).unwrap();
    let expected_wei: U256 = 12341u64.into();
    assert_eq!(expected_wei, wei);
}

#[test]
/// temporary ignore, will refactor later to use dev chain and properly check transaction statuses
fn send_and_refund_erc20_payment() {
    let secret_bytes = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = KeyPair::from_secret_slice(&secret_bytes).unwrap();
    let transport = Web3Transport::new(vec!["https://ropsten.infura.io/v3/c01c1b4cf66642528547624e1d6d9d6b".into()]).unwrap();
    let web3 = Web3::new(transport);
    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = EthCoin(Arc::new(EthCoinImpl {
        ticker: "ETH".into(),
        coin_type: EthCoinType::Erc20(Address::from("0xc0eb7AeD740E1796992A08962c15661bDEB58003")),
        my_address: key_pair.address(),
        priv_key: unwrap!(EcPrivkey::new(CurveType::SECP256K1, &secret_bytes)),
        swap_contract_address: Address::from("0x06964d4DAB22f96c1c382ef6f2b6b8324950f9FD"),
        web3_instances: vec![Web3Instance {web3: web3.clone(), is_parity: false}],
        web3,
        decimals: 18,
        gas_station_url: None,
        history_sync_state: Mutex::new(HistorySyncState::NotStarted),
        ctx: ctx.weak(),
        required_confirmations: 1.into(),
    }));

    let taker_pub = EcPubkey {
        curve_type: CurveType::SECP256K1,
        bytes: unwrap!(hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06")),
    };
    let payment = coin.send_maker_payment(
        &[],
        (now_ms() / 1000) as u32 - 200,
        &taker_pub,
        &SecretHash::default(),
        "0.001".parse().unwrap(),
    ).wait().unwrap();

    log!([payment]);

    thread::sleep(Duration::from_secs(60));

    let refund = coin.send_maker_refunds_payment(
        &[],
        &payment.tx_hex,
        (now_ms() / 1000) as u32 - 200,
        &taker_pub,
        &SecretHash::default(),
    ).wait().unwrap();

    log!([refund]);
}

#[test]
fn send_and_refund_eth_payment() {
    let secret_bytes = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = KeyPair::from_secret_slice(&secret_bytes).unwrap();
    let transport = Web3Transport::new(vec!["http://195.201.0.6:8545".into()]).unwrap();
    let web3 = Web3::new(transport);
    let ctx = MmCtxBuilder::new().into_mm_arc();
    let secret = [0u8; 32];
    let secret_hash = SecretHash::from_secret(SecretHashType::Sha256, &secret);
    let coin = EthCoin(Arc::new(EthCoinImpl {
        ticker: "ETH".into(),
        coin_type: EthCoinType::Eth,
        my_address: key_pair.address(),
        priv_key: unwrap!(EcPrivkey::new(CurveType::SECP256K1, &secret_bytes)),
        swap_contract_address: Address::from("0x06964d4DAB22f96c1c382ef6f2b6b8324950f9FD"),
        web3_instances: vec![Web3Instance {web3: web3.clone(), is_parity: true}],
        web3,
        decimals: 18,
        gas_station_url: None,
        history_sync_state: Mutex::new(HistorySyncState::NotStarted),
        ctx: ctx.weak(),
        required_confirmations: 1.into(),
    }));

    let block = coin.current_block().wait().unwrap();

    let payment = coin.send_maker_payment(
        &[],
        (now_ms() / 1000) as u32 - 200,
        &coin.get_pubkey(),
        &secret_hash,
        "0.001".parse().unwrap(),
    ).wait().unwrap();

    log!([payment]);

    coin.wait_for_confirmations(
        &payment.tx_hex,
        1,
        now_ms() / 1000 + 1000,
        1,
        block,
    ).wait().unwrap();

    let refund = coin.send_maker_refunds_payment(
        &[],
        &payment.tx_hex,
        (now_ms() / 1000) as u32 - 200,
        &coin.get_pubkey(),
        &secret_hash,
    ).wait().unwrap();

    log!([refund]);
}

#[test]
#[ignore]
fn test_nonce_several_urls() {
    let secret_bytes = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = KeyPair::from_secret_slice(&secret_bytes).unwrap();
    let infura_transport = Web3Transport::new(vec!["https://ropsten.infura.io/v3/c01c1b4cf66642528547624e1d6d9d6b".into()]).unwrap();
    let linkpool_transport = Web3Transport::new(vec!["https://ropsten-rpc.linkpool.io".into()]).unwrap();
    // get nonce must succeed if some nodes are down at the moment for some reason
    let failing_transport = Web3Transport::new(vec!["http://195.201.0.6:8989".into()]).unwrap();

    let web3_infura = Web3::new(infura_transport);
    let web3_linkpool = Web3::new(linkpool_transport);
    let web3_failing = Web3::new(failing_transport);

    let ctx = MmCtxBuilder::new().into_mm_arc();
    let coin = EthCoin(Arc::new(EthCoinImpl {
        ticker: "ETH".into(),
        coin_type: EthCoinType::Eth,
        my_address: key_pair.address(),
        priv_key: unwrap!(EcPrivkey::new(CurveType::SECP256K1, &secret_bytes)),
        swap_contract_address: Address::from("0x7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
        web3_instances: vec![
            Web3Instance { web3: web3_infura.clone(), is_parity: false },
            Web3Instance { web3: web3_linkpool, is_parity: false },
            Web3Instance { web3: web3_failing, is_parity: false },
        ],
        web3: web3_infura,
        decimals: 18,
        gas_station_url: Some("https://ethgasstation.info/json/ethgasAPI.json".into()),
        history_sync_state: Mutex::new(HistorySyncState::NotStarted),
        ctx: ctx.weak(),
        required_confirmations: 1.into(),
    }));

    log!("My address " [coin.my_address]);
    log!("before payment");
    let payment = coin.send_to_address(coin.my_address, 200000000.into()).wait().unwrap();

    log!([payment]);
    let new_nonce = get_addr_nonce(coin.my_address, &coin.web3_instances).wait().unwrap();
    log!([new_nonce]);
}

#[test]
fn test_wait_for_payment_spend_timeout() {
    EthCoinImpl::spend_events.mock_safe(|_, _| MockResult::Return(Box::new(futures01::future::ok(vec![]))));

    let secret_bytes = hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap();
    let key_pair = KeyPair::from_secret_slice(&secret_bytes).unwrap();
    let transport = Web3Transport::new(vec!["http://195.201.0.6:8555".into()]).unwrap();
    let web3 = Web3::new(transport);
    let ctx = MmCtxBuilder::new().into_mm_arc();

    let coin = EthCoinImpl {
        coin_type: EthCoinType::Eth,
        decimals: 18,
        gas_station_url: None,
        history_sync_state: Mutex::new(HistorySyncState::NotEnabled),
        my_address: key_pair.address(),
        priv_key: unwrap!(EcPrivkey::new(CurveType::SECP256K1, &secret_bytes)),
        swap_contract_address: Address::from("0x7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
        ticker: "ETH".into(),
        web3_instances: vec![Web3Instance {web3: web3.clone(), is_parity: true}],
        web3,
        ctx: ctx.weak(),
        required_confirmations: 1.into(),
    };

    let coin = EthCoin(Arc::new(coin));
    let wait_until = (now_ms() / 1000) - 1;
    let from_block = 1;
    // raw transaction bytes of https://etherscan.io/tx/0x0869be3e5d4456a29d488a533ad6c118620fef450f36778aecf31d356ff8b41f
    let tx_bytes = [248, 240, 3, 133, 1, 42, 5, 242, 0, 131, 2, 73, 240, 148, 133, 0, 175, 192, 188, 82, 20, 114, 128, 130, 22, 51, 38, 194, 255, 12, 115, 244, 168, 113, 135, 110, 205, 245, 24, 127, 34, 254, 184, 132, 21, 44, 243, 175, 73, 33, 143, 82, 117, 16, 110, 27, 133, 82, 200, 114, 233, 42, 140, 198, 35, 21, 201, 249, 187, 180, 20, 46, 148, 40, 9, 228, 193, 130, 71, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152, 41, 132, 9, 201, 73, 19, 94, 237, 137, 35, 61, 4, 194, 207, 239, 152, 75, 175, 245, 157, 174, 10, 214, 161, 207, 67, 70, 87, 246, 231, 212, 47, 216, 119, 68, 237, 197, 125, 141, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 93, 72, 125, 102, 28, 159, 180, 237, 198, 97, 87, 80, 82, 200, 104, 40, 245, 221, 7, 28, 122, 104, 91, 99, 1, 159, 140, 25, 131, 101, 74, 87, 50, 168, 146, 187, 90, 160, 51, 1, 123, 247, 6, 108, 165, 181, 188, 40, 56, 47, 211, 229, 221, 73, 5, 15, 89, 81, 117, 225, 216, 108, 98, 226, 119, 232, 94, 184, 42, 106];

    assert!(coin.wait_for_tx_spend(&tx_bytes, wait_until, from_block).wait().is_err());
}

#[test]
fn test_withdraw_impl_manual_fee() {
    let (ctx, coin) = eth_coin_for_test(EthCoinType::Eth, vec!["http://dummy.dummy".into()]);

    EthCoin::my_balance.mock_safe(|_| {
        let balance = wei_from_big_decimal(&1000000000.into(), 18).unwrap();
        MockResult::Return(Box::new(futures01::future::ok(balance)))
    });
    get_addr_nonce.mock_safe(|_, _| MockResult::Return(Box::new(futures01::future::ok(0.into()))));

    let withdraw_req = WithdrawRequest {
        amount: 1.into(),
        to: "0x7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94".to_string(),
        coin: "ETH".to_string(),
        max: false,
        fee: Some(WithdrawFee::EthGas { gas: 150000, gas_price: 1.into() }),
    };
    coin.my_balance().wait().unwrap();

    let tx_details = unwrap!(block_on(withdraw_impl(ctx, coin.clone(), withdraw_req)));
    let expected = Some(EthTxFeeDetails {
        coin: "ETH".into(),
        gas_price: "0.000000001".parse().unwrap(),
        gas: 150000,
        total_fee: "0.00015".parse().unwrap(),
    }.into());
    assert_eq!(expected, tx_details.fee_details);
}

#[test]
fn test_nonce_lock() {
    // send several transactions concurrently to check that they are not using same nonce
    // using real ETH dev node
    let (ctx, coin) = eth_coin_for_test(EthCoinType::Eth, vec!["http://195.201.0.6:8565".into()]);
    let mut futures = vec![];
    for _ in 0..5 {
        futures.push(sign_and_send_transaction_impl(
            ctx.clone(),
            coin.clone(),
            1000000000000u64.into(),
            Action::Call(coin.my_address),
            vec![],
            21000.into(),
        ));
    }
    let results = block_on(join_all(futures));
    for result in results {
        unwrap!(result);
    }
    // Waiting for NONCE_LOCK… might not appear at all if waiting takes less than 0.5 seconds
    // but all transactions are sent successfully still
    // unwrap!(wait_for_log(&ctx.log, 1.1, &|line| line.contains("Waiting for NONCE_LOCK…")));
    unwrap!(wait_for_log(&ctx.log, 1.1, &|line| line.contains("get_addr_nonce…")));
}

#[test]
fn test_get_pubkey() {
    let (_, coin) = eth_coin_for_test(EthCoinType::Eth, vec!["http://195.201.0.6:8565".into()]);
    let expected_pub = EcPubkey {
        curve_type: CurveType::SECP256K1,
        bytes: unwrap!(hex::decode("02031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3")),
    };
    assert_eq!(expected_pub, coin.get_pubkey());
}

#[cfg(feature = "w-bindgen")]
mod wasm_bindgen_tests {
    use crate::lp_coininit;
    use super::*;
    use wasm_bindgen_test::*;
    use wasm_bindgen::prelude::*;
    use web_sys::console;

    #[wasm_bindgen_test]
    fn pass() {
        use common::mm_ctx::MmCtxBuilder;
        use super::CoinsContext;
        let ctx = MmCtxBuilder::default().into_mm_arc();
        let coins_context = unwrap!(CoinsContext::from_ctx(&ctx));
        assert_eq!(1, 1);
    }

    #[wasm_bindgen]
    extern "C" {
        fn setInterval(closure: &Closure<FnMut()>, millis: u32) -> f64;
        fn cancelInterval(token: f64);
    }

    wasm_bindgen_test_configure!(run_in_browser);

    pub struct Interval {
        closure: Closure<FnMut()>,
    }

    impl Interval {
        fn new() -> Interval {
            let closure = Closure::new(common::executor::run);
            Interval {
                closure,
            }
        }
    }

    unsafe impl Send for Interval {}

    unsafe impl Sync for Interval {}

    lazy_static! {
        static ref EXECUTOR_INTERVAL: Interval = Interval::new();
    }

    #[wasm_bindgen_test(async)]
    fn test_send() -> impl Future<Item=(), Error=JsValue> {
        setInterval(&EXECUTOR_INTERVAL.closure, 200);
        Box::pin(async move {
            let key_pair = KeyPair::from_secret_slice(&hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap()).unwrap();
            let transport = Web3Transport::new(vec!["http://195.201.0.6:8565".into()]).unwrap();
            let web3 = Web3::new(transport);
            let ctx = MmCtxBuilder::new().into_mm_arc();
            let coin = EthCoin(Arc::new(EthCoinImpl {
                ticker: "ETH".into(),
                coin_type: EthCoinType::Eth,
                my_address: key_pair.address(),
                key_pair,
                swap_contract_address: Address::from("0x7Bc1bBDD6A0a722fC9bffC49c921B685ECB84b94"),
                web3_instances: vec![Web3Instance { web3: web3.clone(), is_parity: true }],
                web3,
                decimals: 18,
                gas_station_url: None,
                history_sync_state: Mutex::new(HistorySyncState::NotStarted),
                ctx: ctx.weak(),
                required_confirmations: 1.into(),
            }));
            let tx = coin.send_maker_payment(
                1000,
                &unwrap!(hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06")),
                &[1; 20],
                "0.001".parse().unwrap(),
            ).compat().await;
            console::log_1(&format!("{:?}", tx).into());

            let block = coin.current_block().compat().await;
            console::log_1(&format!("{:?}", block).into());
            Ok(())
        }).compat()
    }

    #[wasm_bindgen_test(async)]
    fn test_init_eth_coin() -> impl Future<Item=(), Error=JsValue> {
        use common::privkey::key_pair_from_seed;

        setInterval(&EXECUTOR_INTERVAL.closure, 200);
        Box::pin(async move {
            let key_pair = key_pair_from_seed("spice describe gravity federal blast come thank unfair canal monkey style afraid").unwrap();
            let conf = json!({
            "coins": [{
                "coin": "ETH",
                "name": "ethereum",
                "fname": "Ethereum",
                "etomic": "0x0000000000000000000000000000000000000000",
                "rpcport": 80,
                "mm2": 1
            }]
        });
            let ctx = MmCtxBuilder::new().with_conf(conf).with_secp256k1_key_pair(key_pair).into_mm_arc();

            let req = json!({
                "urls":["http://195.201.0.6:8565"],
                "swap_contract_address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            });
            let coin = lp_coininit(&ctx, "ETH", &req).await.unwrap();
            Ok(())
        }).compat()
    }
}
