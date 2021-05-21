use super::*;
use crate::z_coin::z_htlc::z_send_dex_fee;
use common::block_on;
use common::mm_ctx::MmCtxBuilder;
use common::now_ms;
use zcash_client_backend::encoding::decode_extended_spending_key;

use std::sync::Arc;
use std::sync::mpsc::{channel, Sender, Receiver};
use zecwalletlitelib::{commands,
    lightclient::{LightClient, LightClientConfig, DEFAULT_SERVER},
};



pub fn command_loop(lightclient: Arc<LightClient>) -> (Sender<(String, Vec<String>)>, Receiver<String>) {
    let (command_tx, command_rx) = channel::<(String, Vec<String>)>();
    let (resp_tx, resp_rx) = channel::<String>();

    let lc = lightclient.clone();
    std::thread::spawn(move || {
        loop {
            match command_rx.recv_timeout(std::time::Duration::from_secs(5 * 60)) {
                Ok((cmd, args)) => {
                    let args = args.iter().map(|s| s.as_ref()).collect();

                    let cmd_response = commands::do_user_command(&cmd, &args, lc.as_ref());
                    resp_tx.send(cmd_response).unwrap();

                    if cmd == "quit" {
                        println!("Quit");
                        break;
                    }
                },
                Err(_) => {
                    // Timeout. Do a sync to keep the wallet up-to-date. False to whether to print updates on the console
                    println!("Timeout, doing a sync");
                    match lc.do_sync(false) {
                        Ok(_) => {},
                        Err(e) => {println!("{}", e)}
                    }
                }
            }
        }
    });

    (command_tx, resp_rx)
}

#[test]
pub fn zstartup() { //server: http::Uri, seed: Option<String>, birthday: u64, first_sync: bool, print_updates: bool)
        //-> io::Result<(Sender<(String, Vec<String>)>, Receiver<String>)> {
    
    // Try to get the configuration

    let seed = "pudding lock slam choose answer medal tank museum ride stadium collect strong occur capital tennis error jungle circle wheel learn cabin dog dirt age".to_string();

    let birthday :u64 = 1254007;
    let first_sync = true;
    let print_updates = true;
    // /let server = DEFAULT_SERVER;
    let server = LightClientConfig::get_server_or_default(Some(DEFAULT_SERVER.to_string()));

    let (config, latest_block_height) = LightClientConfig::create(server.clone()).unwrap();

    let lightclient = Arc::new(LightClient::new_from_phrase(seed, &config, birthday, false).unwrap());


    // Print startup Messages
    println!(""); // Blank line
    println!("Starting Zecwallet-CLI");
    println!("Light Client config {:?}", config);

    if print_updates {
        println!("Lightclient connecting to {}", config.server);
    }

    // At startup, run a sync.
    if first_sync {
        let update = lightclient.do_sync(true);
        if print_updates {
            match update {
                Ok(j) => {
                    println!("{}", j.pretty(2));
                },
                Err(e) => println!("{}", e)
            }
        }
    }

    // Start the command loop
    let (command_tx, resp_rx) = command_loop(lightclient.clone());

    command_tx.send(("balance".to_string(), Vec::new() )).unwrap();

    match resp_rx.recv() {
        Ok(s) => println!("{}", s),
        Err(e) => {
            let e = format!("Error executing command {}: {}", "balances".to_string(), e);
            eprintln!("{}", e);
            println!("{}", e);
        }
    }

    // Save before exit
    command_tx.send(("save".to_string(), vec![])).unwrap();
    resp_rx.recv().unwrap();

    //Ok((command_tx, resp_rx))
}
/*
fn test_init_lite() {


    let (command_tx, resp_rx) = match startup(server, seed, birthday, !nosync, command.is_none()) {
        Ok(c) => c,
        Err(e) => {
            let emsg = format!("Error during startup:{}\nIf you repeatedly run into this issue, you might have to restore your wallet from your seed phrase.", e);
            eprintln!("{}", emsg);
            error!("{}", emsg);
            if cfg!(target_os = "unix" ) {
                match e.raw_os_error() {
                    Some(13) => report_permission_error(),
                    _        => {},
                }
            };
            return;
        }
    };
}
*/

#[test]
fn zombie_coin_send_and_refund_maker_payment() {
    let conf = json!({
        "coin": "ZOMBIE",
        "asset": "ZOMBIE",
        "fname": "ZOMBIE (TESTCOIN)",
        "txversion": 4,
        "overwintered": 1,
        "mm2": 1,
    });
    let req = json!({
        "method": "enable",
        "coin": "ZOMBIE"
    });

    let ctx = MmCtxBuilder::default().into_mm_arc();
    let priv_key = [1; 32];
    let z_key = decode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, "secret-extended-key-main1q0k2ga2cqqqqpq8m8j6yl0say83cagrqp53zqz54w38ezs8ly9ly5ptamqwfpq85u87w0df4k8t2lwyde3n9v0gcr69nu4ryv60t0kfcsvkr8h83skwqex2nf0vr32794fmzk89cpmjptzc22lgu5wfhhp8lgf3f5vn2l3sge0udvxnm95k6dtxj2jwlfyccnum7nz297ecyhmd5ph526pxndww0rqq0qly84l635mec0x4yedf95hzn6kcgq8yxts26k98j9g32kjc8y83fe").unwrap().unwrap();

    let coin = block_on(z_coin_from_conf_and_request_with_z_key(
        &ctx, "ZOMBIE", &conf, &req, &priv_key, z_key,
    ))
    .unwrap();

    let lock_time = (now_ms() / 1000) as u32 - 3600;
    let taker_pub = coin.utxo_arc.key_pair.public();
    let secret_hash = [0; 20];
    let tx = coin
        .send_maker_payment(lock_time, &*taker_pub, &secret_hash, "0.01".parse().unwrap(), &None)
        .wait()
        .unwrap();
    println!("swap tx {}", hex::encode(&tx.tx_hash().0));

    let refund_tx = coin
        .send_maker_refunds_payment(&tx.tx_hex(), lock_time, &*taker_pub, &secret_hash, &None)
        .wait()
        .unwrap();
    println!("refund tx {}", hex::encode(&refund_tx.tx_hash().0));
}

#[test]
fn zombie_coin_send_and_spend_maker_payment() {
    let conf = json!({
        "coin": "ZOMBIE",
        "asset": "ZOMBIE",
        "fname": "ZOMBIE (TESTCOIN)",
        "txversion": 4,
        "overwintered": 1,
        "mm2": 1,
    });
    let req = json!({
        "method": "enable",
        "coin": "ZOMBIE"
    });

    let ctx = MmCtxBuilder::default().into_mm_arc();
    let priv_key = [1; 32];
    let z_key = decode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, "secret-extended-key-main1q0k2ga2cqqqqpq8m8j6yl0say83cagrqp53zqz54w38ezs8ly9ly5ptamqwfpq85u87w0df4k8t2lwyde3n9v0gcr69nu4ryv60t0kfcsvkr8h83skwqex2nf0vr32794fmzk89cpmjptzc22lgu5wfhhp8lgf3f5vn2l3sge0udvxnm95k6dtxj2jwlfyccnum7nz297ecyhmd5ph526pxndww0rqq0qly84l635mec0x4yedf95hzn6kcgq8yxts26k98j9g32kjc8y83fe").unwrap().unwrap();

    let coin = block_on(z_coin_from_conf_and_request_with_z_key(
        &ctx, "ZOMBIE", &conf, &req, &priv_key, z_key,
    ))
    .unwrap();

    let lock_time = (now_ms() / 1000) as u32 - 1000;
    let taker_pub = coin.utxo_arc.key_pair.public();
    let secret = [0; 32];
    let secret_hash = dhash160(&secret);
    let tx = coin
        .send_maker_payment(lock_time, &*taker_pub, &*secret_hash, "0.01".parse().unwrap(), &None)
        .wait()
        .unwrap();
    println!("swap tx {}", hex::encode(&tx.tx_hash().0));

    let maker_pub = taker_pub;
    let spend_tx = coin
        .send_taker_spends_maker_payment(&tx.tx_hex(), lock_time, &*maker_pub, &secret, &None)
        .wait()
        .unwrap();
    println!("spend tx {}", hex::encode(&spend_tx.tx_hash().0));
}

#[test]
fn zombie_coin_send_and_refund_dex_fee() {
    let conf = json!({
        "coin": "ZOMBIE",
        "asset": "ZOMBIE",
        "fname": "ZOMBIE (TESTCOIN)",
        "txversion": 4,
        "overwintered": 1,
        "mm2": 1,
    });
    let req = json!({
        "method": "enable",
        "coin": "ZOMBIE"
    });

    let ctx = MmCtxBuilder::default().into_mm_arc();
    let priv_key = [1; 32];
    let z_key = decode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, "secret-extended-key-main1q0k2ga2cqqqqpq8m8j6yl0say83cagrqp53zqz54w38ezs8ly9ly5ptamqwfpq85u87w0df4k8t2lwyde3n9v0gcr69nu4ryv60t0kfcsvkr8h83skwqex2nf0vr32794fmzk89cpmjptzc22lgu5wfhhp8lgf3f5vn2l3sge0udvxnm95k6dtxj2jwlfyccnum7nz297ecyhmd5ph526pxndww0rqq0qly84l635mec0x4yedf95hzn6kcgq8yxts26k98j9g32kjc8y83fe").unwrap().unwrap();

    let coin = block_on(z_coin_from_conf_and_request_with_z_key(
        &ctx, "ZOMBIE", &conf, &req, &priv_key, z_key,
    ))
    .unwrap();

    let lock_time = (now_ms() / 1000) as u32 - 1000;
    let watcher_pub = coin.utxo_arc.key_pair.public();
    let (tx, redeem_script) = block_on(z_send_dex_fee(&coin, lock_time, watcher_pub, "0.01".parse().unwrap())).unwrap();
    println!("dex fee tx {}", hex::encode(&*tx.hash().reversed()));

    let script_data = ScriptBuilder::default().push_opcode(Opcode::OP_1).into_script();
    let refund = block_on(z_p2sh_spend(
        &coin,
        tx,
        lock_time,
        SEQUENCE_FINAL - 1,
        redeem_script,
        script_data,
    ))
    .unwrap();
    println!("dex fee refund tx {}", hex::encode(&*refund.hash().reversed()));
}

#[test]
fn zombie_coin_send_and_spend_dex_fee() {
    let conf = json!({
        "coin": "ZOMBIE",
        "asset": "ZOMBIE",
        "fname": "ZOMBIE (TESTCOIN)",
        "txversion": 4,
        "overwintered": 1,
        "mm2": 1,
    });
    let req = json!({
        "method": "enable",
        "coin": "ZOMBIE"
    });

    let ctx = MmCtxBuilder::default().into_mm_arc();
    let priv_key = [1; 32];
    let z_key = decode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, "secret-extended-key-main1q0k2ga2cqqqqpq8m8j6yl0say83cagrqp53zqz54w38ezs8ly9ly5ptamqwfpq85u87w0df4k8t2lwyde3n9v0gcr69nu4ryv60t0kfcsvkr8h83skwqex2nf0vr32794fmzk89cpmjptzc22lgu5wfhhp8lgf3f5vn2l3sge0udvxnm95k6dtxj2jwlfyccnum7nz297ecyhmd5ph526pxndww0rqq0qly84l635mec0x4yedf95hzn6kcgq8yxts26k98j9g32kjc8y83fe").unwrap().unwrap();

    let coin = block_on(z_coin_from_conf_and_request_with_z_key(
        &ctx, "ZOMBIE", &conf, &req, &priv_key, z_key,
    ))
    .unwrap();

    let lock_time = (now_ms() / 1000) as u32 - 1000;
    let watcher_pub = coin.utxo_arc.key_pair.public();
    let (tx, redeem_script) = block_on(z_send_dex_fee(&coin, lock_time, watcher_pub, "0.01".parse().unwrap())).unwrap();
    println!("dex fee tx {}", hex::encode(&*tx.hash().reversed()));

    let script_data = ScriptBuilder::default().push_opcode(Opcode::OP_0).into_script();
    let spend = block_on(z_p2sh_spend(
        &coin,
        tx,
        lock_time,
        SEQUENCE_FINAL,
        redeem_script,
        script_data,
    ))
    .unwrap();
    println!("dex fee spend tx {}", hex::encode(&*spend.hash().reversed()));
}

#[test]
fn derive_z_key_from_mm_seed() {
    use common::privkey::key_pair_from_seed;
    use zcash_client_backend::encoding::encode_extended_spending_key;

    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";
    let secp_keypair = key_pair_from_seed(seed).unwrap();
    let z_spending_key = ExtendedSpendingKey::master(&*secp_keypair.private().secret);
    let encoded = encode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, &z_spending_key);
    assert_eq!(encoded, "secret-extended-key-main1qqqqqqqqqqqqqqytwz2zjt587n63kyz6jawmflttqu5rxavvqx3lzfs0tdr0w7g5tgntxzf5erd3jtvva5s52qx0ms598r89vrmv30r69zehxy2r3vesghtqd6dfwdtnauzuj8u8eeqfx7qpglzu6z54uzque6nzzgnejkgq569ax4lmk0v95rfhxzxlq3zrrj2z2kqylx2jp8g68lqu6alczdxd59lzp4hlfuj3jp54fp06xsaaay0uyass992g507tdd7psua5w6q76dyq3");

    let (_, address) = z_spending_key.default_address().unwrap();
    let encoded_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &address);
    assert_eq!(
        encoded_addr,
        "zs182ht30wnnnr8jjhj2j9v5dkx3qsknnr5r00jfwk2nczdtqy7w0v836kyy840kv2r8xle5gcl549"
    );
}

// create a "lite wallet"; import mm2 phrase derived z address
#[test]
fn wallet_from_mm2_seed() {
    use common::privkey::key_pair_from_seed;
    use zcash_client_backend::encoding::encode_extended_spending_key;
    use json::array;

    let dummy_seed = "pudding lock slam choose answer medal tank museum ride stadium collect strong occur capital tennis error jungle circle wheel learn cabin dog dirt age".to_string();
    let birthday :u64 = 1254007;

    let config = LightClientConfig::create_unconnected("main".to_string(), None);

    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";
    let secp_keypair = key_pair_from_seed(seed).unwrap();
    let z_spending_key = ExtendedSpendingKey::master(&*secp_keypair.private().secret);
    let encoded :String = encode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, &z_spending_key);

    let lightclient = Arc::new(LightClient::new_from_phrase(dummy_seed, &config, birthday, false).unwrap());

    let (_, address) = z_spending_key.default_address().unwrap();
    let encoded_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &address);

    let json_ret = lightclient.do_import_sk(encoded, birthday).unwrap();

    assert_eq!(array![encoded_addr], json_ret);
}
