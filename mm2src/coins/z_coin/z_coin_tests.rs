use super::*;
use common::block_on;
use common::mm_ctx::MmCtxBuilder;
use zcash_client_backend::encoding::decode_extended_spending_key;

#[test]
fn zombie_coin_init() {
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
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";
    let secp_keypair = key_pair_from_seed(seed).unwrap();
    let z_key = ExtendedSpendingKey::master(&*secp_keypair.private().secret);

    let coin = block_on(z_coin_from_conf_and_request(
        &ctx,
        "ZOMBIE",
        &conf,
        &req,
        &*secp_keypair.private().secret,
        z_key,
    ))
    .unwrap();

    let balance = coin.my_balance().wait().unwrap();
    let expected_balance: BigDecimal = 1.into();
    assert_eq!(expected_balance, balance.spendable);
}

#[test]
fn zombie_coin_send_htlc_maker_payment() {
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

    let coin = block_on(z_coin_from_conf_and_request(
        &ctx, "ZOMBIE", &conf, &req, &priv_key, z_key,
    ))
    .unwrap();

    let lock_time = 1620382880;
    let taker_pub = coin.utxo_arc.key_pair.public();
    let secret_hash = [0; 20];
    let tx = coin
        .send_maker_payment(lock_time, &*taker_pub, &secret_hash, "0.01".parse().unwrap(), &None)
        .wait()
        .unwrap();
    println!("{:?}", hex::encode(&tx.tx_hash().0));
}
