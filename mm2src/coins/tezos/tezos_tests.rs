use super::*;
use crate::tezos::tezos_rpc::OperationsResult;

fn tezos_coin_for_test() -> TezosCoin {
    let conf = json!({
        "coin": "DUNETEST",
        "name": "dunetestnet",
        "ed25519_addr_prefix": [4, 177, 1],
        "secp256k1_addr_prefix": [4, 177, 3],
        "p256_addr_prefix": [4, 177, 6],
        "protocol": {
          "platform": "TEZOS",
          "token_type": "TEZOS"
        },
        "mm2": 1
    });
    let req = json!({
        "method": "enable",
        "coin": "DUNETEST",
        "urls": [
            "https://testnet-node.dunscan.io"
        ],
        "mm2":1
    });
    let priv_key = hex::decode("0760b6189e10610d3800d75d14ffe2f0abb35f8bf612a9510b5598d978f83f7a").unwrap();
    let coin = block_on(tezos_coin_from_conf_and_request("DUNETEST", &conf, &req, &priv_key)).unwrap();
    coin
}

fn tezos_erc_coin_for_test() -> TezosCoin {
    let conf = json!({
        "coin": "DUNETESTERC",
        "name": "dunetesterc",
        "ed25519_addr_prefix": [4, 177, 1],
        "secp256k1_addr_prefix": [4, 177, 3],
        "p256_addr_prefix": [4, 177, 6],
        "protocol": {
            "platform": "TEZOS",
            "token_type": "ERC20",
            "contract_address": "KT1Bzq2mPvZk6jdmSzvVySXrQhYrybPnnxyZ"
        },
        "mm2": 1
    });
    let req = json!({
        "method": "enable",
        "coin": "DUNETESTERC",
        "urls": [
            "https://testnet-node.dunscan.io"
        ],
        "mm2":1
    });
    let priv_key = hex::decode("0760b6189e10610d3800d75d14ffe2f0abb35f8bf612a9510b5598d978f83f7a").unwrap();
    let coin = block_on(tezos_coin_from_conf_and_request("DUNETEST", &conf, &req, &priv_key)).unwrap();
    coin
}

#[test]
fn test_extract_secret() {
    let tx_bytes = unwrap!(hex::decode("ed0dd721b69a9caa34631c12de656294f40769eadc0f472f4cb86cccb643bae90800002969737230bd5ea60f632b52777981e43a25d069a08d069b0580ea30e0d40300011a8f7a22dd852d1c8542d795eae3b094a7c629aa00ff0000006e0005080508050507070a000000103bf685c8da0c4cbb9766ab46d36d5c9b07070a0000002000000000000000000000000000000000000000000000000000000000000000000100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779708ea21a6d1d3dfaf448f9ac095c456a43c2e08f9e148cf84f215cb888bdd36c28eaf0b351a063f71ac293112a9c8bf8ad6d38b6e47b1b8c84d2a1cb0d8044500f"));
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let secret = unwrap!(op.extract_secret());
    assert_eq!(vec![0; 32], secret);
}

#[test]
fn test_tezos_int_binary_serde() {
    let bytes = vec![1];
    let num: TezosInt = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num.0, BigInt::from(1));

    let num = TezosInt(BigInt::from(128700i64));
    let bytes = serialize(&num).take();
    assert_eq!(vec![188, 218, 15], bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosInt(BigInt::from(8192u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("808001")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosInt(BigInt::from(-8192i64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("c08001")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosInt(BigInt::from(-1000000000i64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("c0a8d6b907")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosInt(BigInt::from(1000000000i64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("80a8d6b907")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);
}

#[test]
fn test_tezos_uint_binary_serde() {
    let bytes = vec![1];
    let num: TezosUint = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num.0, BigUint::from(1u8));

    let num = TezosUint(BigUint::from(128700u64));
    let bytes = serialize(&num).take();
    assert_eq!(vec![188, 237, 7], bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosUint(BigUint::from(1000000u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("c0843d")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosUint(BigUint::from(2000000u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("80897a")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosUint(BigUint::from(1420u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("8c0b")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosUint(BigUint::from(127u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("7f")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosUint(BigUint::from(128u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("8001")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);

    let num = TezosUint(BigUint::from(129u64));
    let bytes = serialize(&num).take();
    assert_eq!(unwrap!(hex::decode("8101")), bytes);
    let deserialized = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num, deserialized);
}

#[test]
fn test_tezos_atomic_swap_from_value() {
    let json_str = r#"{"prim":"Pair","args":[{"int":"100000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"prim":"None"},{"prim":"Pair","args":[{"int":"1574680671"},{"prim":"Pair","args":[{"int":"1574696229"},{"prim":"Pair","args":[{"bytes":"0000dfea0bdd3adff1b8072ea45beea66b00c9cbd918"},{"prim":"Pair","args":[{"bytes":"b795e8c0c862d82136c0b23a913453fe5dcccce5161fa248c2c22209b8890f43"},{"prim":"Pair","args":[{"bytes":"00002969737230bd5ea60f632b52777981e43a25d069"},{"prim":"Pair","args":[{"prim":"Some","args":[{"int":"1574680761"}]},{"prim":"Pair","args":[{"prim":"Right","args":[{"prim":"Left","args":[{"prim":"Unit"}]}]},{"bytes":"65383063303832652d646135392d346165382d383064322d38396162613934616361636200"}]}]}]}]}]}]}]}]}]}]}"#;
    let value: TezosValue = unwrap!(json::from_str(json_str));
    let swap = unwrap!(TezosAtomicSwap::try_from(value));
}

#[test]
fn test_operation_serde() {
    let tx_hex = "ef48deeeae27573e2c77f3c5c011af40437ffebde394f343a1545e82d39f854d0800002969737230bd5ea60f632b52777981e43a25d069a08d06e00480ea30e0d403c0843d01192109476f194a603982c1cfc028b5fad65b789100ff0000007600050507070a000000012507070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f29250100000024646e314b75746668346577744e7875394663774448667a375834535775575a6452477970d110ea0d70706147276244fc231f71d4452e4dde51647595d984aa49ce95aee2928aa521bd4a316ee29b2cc62d56e8c8a750208062abf0d19077c637310ec201";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "4ea793fe179be186e7cad783eb797d5ef00e4e91b840d856172dc3ee51ddafe90800002969737230bd5ea60f632b52777981e43a25d069a08d06ee0480ea30e0d40300011a8f7a22dd852d1c8542d795eae3b094a7c629aa00ff000000a7000508050507070a000000011307070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f292507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700707000101000000244b5431427a71326d50765a6b366a646d537a765679535872516859727962506e6e78795a079655d5c2b8c864945c698dc49de289ebc041f14eff57436cbd6beed52b455c80983e94352f080fa209177bd4f347fd026b891b122fdc9bd7f47c974780e303";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "490b0c37ce1bc176dba3d711f78cd6f76416f2720804e46462e3117c7968ad2c080000dfea0bdd3adff1b8072ea45beea66b00c9cbd918a08d06b30980ea30e0d4030001627e152ed31cd79d77ba6c982ee9271684f3808200ff0000003200050507070100000024646e3247626d62576a4e56777742626154384354506a6e3177795757537376343739645a00bcda0f5feddfd6594743775b3b315d298f7ba30470c18c3f68144c4e1f2991e5139d1ed1f1a19d42bbb783689a3846d0587b28eb0bba98a860b1a26970fe2cb9152c0d";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "fddf2e2bf3b66a92194ed46eba439117793371d6c68fe25bab94d921d0b30c0d0800002969737230bd5ea60f632b52777981e43a25d069a08d06a60580ea30e0d403c0843d011a8f7a22dd852d1c8542d795eae3b094a7c629aa00ff0000009900050507070a0000002437353131303666352d346536622d346536372d393736632d34643331303032623761623807070100000014323031392d31312d32315431393a33373a31305a07070a0000002071b58010b26553a2a6f37fd9515d9c843561c9c0c2d8a762f293e2cbecc8695a0100000024646e31635973685a76756b6a326d63705064717142447379696f357957664d66646e794d672c7a5de62a7fa70c3b9385cbe2a1f79ec721ac44c0a5c8675e59b6eb51f64ba240f10568214024c87a807893b16abfae5e89e0b39152285cee02faeda92a0b";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);
}

#[test]
fn test_tezos_rpc_value_binary_serialization() {
    let expected_bytes = unwrap!(hex::decode("0100000024646e314b75746668346577744e7875394663774448667a375834535775575a6452477970"));
    let value = TezosValue::String {
        string: "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".into()
    };
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("0080a8d6b907"));
    let value = TezosValue::Int {
        int: BigInt::from(1000000000i64).into()
    };
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("07070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700080a8d6b907"));
    let value = TezosValue::TezosPrim(TezosPrim::Pair ((
        Box::new(TezosValue::String {
            string: "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".into()
        }),
        Box::new(TezosValue::Int {
            int: BigInt::from(1000000000i64).into()
        }),
    )));
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("050507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700080a8d6b907"));
    let value = TezosValue::TezosPrim(TezosPrim::Left([
        Box::new(value)
    ]));
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("0508050507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700080a8d6b907"));
    let value = TezosValue::TezosPrim(TezosPrim::Right([
        Box::new(value)
    ]));
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);
}

#[test]
fn test_construct_function_call() {
    let id = BytesJson(vec![1]);
    let timestamp: DateTime<Utc> = "1970-01-01T00:00:00Z".parse().unwrap();
    let secret_hash: BytesJson = hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap().into();
    let address: TezosAddress = "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".parse().unwrap();
    let call = tezos_func!(&[Or::L], id, timestamp, secret_hash, address);
    let expected = r#"{"prim":"Left","args":[{"prim":"Pair","args":[{"bytes":"01"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"}]}]}]}]}"#;
    assert_eq!(expected, json::to_string(&call).unwrap());

    let id = BytesJson(vec![0x10]);
    let timestamp = DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
    let secret_hash: BytesJson = hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap().into();
    let address: TezosAddress = "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".parse().unwrap();
    let call = tezos_func!(&[Or::R, Or::L], id, timestamp, secret_hash, address);
    let expected = r#"{"prim":"Right","args":[{"prim":"Left","args":[{"prim":"Pair","args":[{"bytes":"10"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"}]}]}]}]}]}"#;
    assert_eq!(expected, json::to_string(&call).unwrap());

    let call = tezos_func!(&[Or::L]);
    let expected = r#"{"prim":"Left","args":[{"prim":"Unit"}]}"#;
    assert_eq!(expected, json::to_string(&call).unwrap());
}

#[test]
fn deserialize_erc_storage() {
    let json = r#"{"prim":"Pair","args":[[],{"prim":"Pair","args":[{"int":"1"},{"prim":"Pair","args":[{"int":"100000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"string":"TEST"},{"prim":"Pair","args":[{"string":"TEST"},{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"}]}]}]}]}]}]}"#;
    let pair: TezosValue = json::from_str(&json).unwrap();
    log!([pair]);
    let storage = unwrap!(TezosErcStorage::try_from(pair));
    log!([storage]);
}

#[test]
fn deserialize_erc_account() {
    let json = r#"{"prim":"Pair","args":[{"int":"99984"},[{"prim":"Elt","args":[{"bytes":"01088e02012f75cdee43326dfdec205f7bfd30dd6c00"},{"int":"990"}]},{"prim":"Elt","args":[{"bytes":"0122bef431640e29dd4a01cf7cc5befac05f0b99b700"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0152f0ecfb244e2b393b60263d8ae60ac13d08472900"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0153663d8ad9f9c6b28f94508599a255b6c2c5b0c900"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0153d475620cccc1cdb1fb2e1d20c2c713a729fc5100"},{"int":"1"}]},{"prim":"Elt","args":[{"bytes":"015eef25239095cfef6325bbbe7671821d0761936e00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0164ba0f8a211f0584171b47e1c7d00686d80642d600"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0169ad9656ad447d6394c0dae64588f307f47ac37500"},{"int":"1000"}]},{"prim":"Elt","args":[{"bytes":"017d8c19f42235a54c7e932cf0120a9b869a141fad00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"01c90438d5b073d5d8bde6f2cd24957f911bd78beb00"},{"int":"998"}]},{"prim":"Elt","args":[{"bytes":"01d2fd4e3c7cb8a766462c02d388b530ce40192f5c00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"01fcf0818b6d79358258675f07451f8de76ff8626e00"},{"int":"999"}]}]]}"#;
    let rpc_value: TezosValue = json::from_str(&json).unwrap();
    let erc_account = unwrap!(TezosErcAccount::try_from(rpc_value));
}

#[test]
fn tezos_signature_from_to_string() {
    let sig_str = "edsigtrFyTY19vJ4XFdrK8uUM3qHzE6427u4JYRNsMtzdBqQvPPnKZYE3xps25CEPm2yTXu53Po16Z523PHG7jzgowb3X75w66Y";
    let sig: TezosSignature = sig_str.parse().unwrap();
    assert_eq!(sig_str, sig.to_string());

    let sig_str = "sigWjGCa4UrrXx92BwbPUfC5vyBUFwS2a5r6NJTba67Vev6JUJJjs4SWT3G8HFRnkfPabRExGZrMGjNahBpYnr6ZY81TUkqm";
    let sig: TezosSignature = sig_str.parse().unwrap();
    assert_eq!(sig_str, sig.to_string());
}

#[test]
fn operation_hash_from_to_string() {
    let op_hash_str = "op9z9QouqrxjnE4RRQ86PCvhLLQcyKoWBoHBLX6BRE8JqBmcKWe";
    let op_hash: OpHash = op_hash_str.parse().unwrap();
    assert_eq!(op_hash_str, op_hash.to_string());
}

#[test]
fn operation_hash_from_op_bytes() {
    let bytes = unwrap!(hex::decode("490b0c37ce1bc176dba3d711f78cd6f76416f2720804e46462e3117c7968ad2c080000dfea0bdd3adff1b8072ea45beea66b00c9cbd918a08d06b30980ea30e0d4030001627e152ed31cd79d77ba6c982ee9271684f3808200ff0000003200050507070100000024646e3247626d62576a4e56777742626154384354506a6e3177795757537376343739645a00bcda0f5feddfd6594743775b3b315d298f7ba30470c18c3f68144c4e1f2991e5139d1ed1f1a19d42bbb783689a3846d0587b28eb0bba98a860b1a26970fe2cb9152c0d"));
    let op_hash = OpHash::from_op_bytes(&bytes);
    assert_eq!("ooAzqChsWPptuDcth9cH7ACqiC5HoVYthA9FMdQVjKoftMbW1jA", op_hash.to_string());
}

#[test]
fn key_pair_get_address() {
    let key_pair: TezosKeyPair = unwrap!("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ".parse());
    let expected = TezosAddress {
        prefix: [6, 161, 159],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!(expected, key_pair.get_address([6, 161, 159]));
}

#[test]
fn tezos_address_from_to_string() {
    let address = TezosAddress {
        prefix: [6, 161, 159],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU")));
}

#[test]
fn tezos_pubkey_from_to_string() {
    let pubkey = TezosPubkey {
        prefix: [13, 15, 37, 217],
        bytes: vec![166, 202, 119, 231, 228, 189, 30, 242, 46, 204, 159, 12, 12, 218, 180, 41, 168, 96, 249, 96, 99, 204, 81, 186, 149, 15, 209, 40, 198, 67, 175, 141],
    };

    assert_eq!(pubkey, unwrap!(TezosPubkey::from_str("edpkuugPN19icgASNMSTiVFeF4F1htia8YwA67ZANiMUEFTEzMZ4dQ")));
    assert_eq!("edpkuugPN19icgASNMSTiVFeF4F1htia8YwA67ZANiMUEFTEzMZ4dQ", pubkey.to_string());
}

#[test]
fn tezos_block_hash_from_to_string() {
    let block_hash = TezosBlockHash {
        prefix: [1, 52],
        hash: H256::from([179, 210, 18, 192, 241, 185, 183, 107, 195, 238, 140, 247, 125, 33, 193, 145, 186, 39, 80, 186, 231, 132, 73, 236, 217, 134, 218, 226, 45, 91, 94, 180]),
    };

    assert_eq!("BM5UcRC5rLiajhwDNEmF3mF152f2Uiaqsj9CFTr4WyQvCsaY4pm", block_hash.to_string());
    assert_eq!(block_hash, unwrap!(TezosBlockHash::from_str("BM5UcRC5rLiajhwDNEmF3mF152f2Uiaqsj9CFTr4WyQvCsaY4pm")));
}

#[test]
fn dune_address_from_to_string() {
    let address = TezosAddress {
        prefix: [4, 177, 1],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By")));

    let address = TezosAddress {
        prefix: [4, 177, 3],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn2QkyrG831hiqQBTzdJWMbdeAhzzNcD1qE6", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn2QkyrG831hiqQBTzdJWMbdeAhzzNcD1qE6")));

    let address = TezosAddress {
        prefix: [4, 177, 6],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn3cmnob1u9F7TrUtFhZWK41TXbWmCnHRWw9", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn3cmnob1u9F7TrUtFhZWK41TXbWmCnHRWw9")));

    let address = TezosAddress {
        prefix: [2, 90, 121],
        hash: H160::from([26, 143, 122, 34, 221, 133, 45, 28, 133, 66, 215, 149, 234, 227, 176, 148, 167, 198, 41, 170]),
    };

    assert_eq!(address, unwrap!(TezosAddress::from_str("KT1B1D1iVrVyrABRRp6PxPU894dzWghvt4mf")));
    assert_eq!("KT1B1D1iVrVyrABRRp6PxPU894dzWghvt4mf", address.to_string());
}

#[test]
fn tezos_key_pair_from_to_string() {
    let key_pair = TezosKeyPair::ED25519(EdKeypair {
        secret: unwrap!(EdSecretKey::from_bytes(&[197, 109, 203, 119, 241, 255, 240, 13, 26, 31, 83, 48, 167, 122, 159, 31, 49, 207, 112, 250, 122, 214, 145, 162, 43, 94, 194, 140, 219, 35, 35, 80])),
        public: unwrap!(EdPublicKey::from_bytes(&[107, 106, 160, 0, 4, 28, 170, 101, 209, 223, 114, 53, 77, 50, 155, 234, 226, 167, 130, 197, 144, 33, 242, 92, 111, 64, 191, 74, 136, 120, 28, 27])),
    });

    assert_eq!("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ", key_pair.to_string());
    assert_eq!(key_pair, unwrap!(TezosKeyPair::from_str("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ")));

    let key_pair: TezosKeyPair = "edsk2j9jaipLSH77rtwZFroZqEoSkr5fFUzcPqhphBH3BKudQU9rtw".parse().unwrap();
    log!([key_pair]);
    log!((hex::encode([7, 96, 182, 24, 158, 16, 97, 13, 56, 0, 215, 93, 20, 255, 226, 240, 171, 179, 95, 139, 246, 18, 169, 81, 11, 85, 152, 217, 120, 248, 63, 122])));
}

#[test]
fn test_check_if_my_taker_payment_sent() {
    let coin = tezos_coin_for_test();
    let uuid = unwrap!(hex::decode("65383063303832652d646135392d346165382d383064322d383961626139346163616362"));
    let tx = coin.check_if_my_taker_payment_sent(
        &uuid,
        0,
        &coin.get_pubkey(),
        &[],
        202994,
    ).wait().unwrap();
    let tx = unwrap!(tx);
    assert_eq!("ooZY3Lz9r6XcceDgB9pvzdt8LXdasJoCCk1P1k2ZyBwxaJSZ5ks", coin.tx_hash_to_string(&tx.tx_hash()));
    log!((hex::encode(tx.tx_hex())));
}

#[test]
fn test_check_if_my_maker_payment_sent() {
    let coin = tezos_coin_for_test();
    let uuid = unwrap!(hex::decode("65383063303832652d646135392d346165382d383064322d383961626139346163616362"));
    let tx = coin.check_if_my_maker_payment_sent(
        &uuid,
        0,
        &coin.get_pubkey(),
        &[],
        202994,
    ).wait().unwrap();
    let tx = unwrap!(tx);
    assert_eq!("ooKKQQN5mFHsgeJLw6EbpiHn9auqPub44uqtNMfrNMkbFQhiWXP", coin.tx_hash_to_string(&tx.tx_hash()));
}

#[test]
fn test_wait_for_tx_spend() {
    let coin = tezos_erc_coin_for_test();
    let tx = unwrap!(hex::decode("a5a3da0a35a3722035f916879e71d8f420e0bbc59821ee5b48f91e88e9c8111c080000dfea0bdd3adff1b8072ea45beea66b00c9cbd918a08d06950a80ea30e0d4030001a1b26740e4d3d718c06a5ed58a59ba27d29b6ef500ff000000ce000508050507070a0000002565383063303832652d646135392d346165382d383064322d3839616261393461636163620107070100000014323031392d31312d32355431333a32373a30395a07070a00000020b795e8c0c862d82136c0b23a913453fe5dcccce5161fa248c2c22209b8890f4307070100000024646e314b75746668346577744e7875394663774448667a375834535775575a645247797007070080dac40901000000244b5431485a597077756e4271554834786672646d50396d364c766852787a48327957356389799e22c430f2b24deb5d949b4f249ad1b4e0110528253faf1122a8a4f1d84dfffdcd25829cfdead36987f67c16cfcd1b92d8f91ac3e74e274c84a1d9855103"));
    let spend = unwrap!(coin.wait_for_tx_spend(
        &tx,
        now_ms() / 1000 + 300,
        202994,
    ).wait());
    assert_eq!("onehiS6GMdSAwcVKnxKf2SaFUbYiuFiKVcKD1oJMzueHNVCkMtN", coin.tx_hash_to_string(&spend.tx_hash()));
}

#[test]
fn test_search_for_swap_spend_tx_my() {
    let coin = tezos_erc_coin_for_test();
    let tx = unwrap!(hex::decode("a5a3da0a35a3722035f916879e71d8f420e0bbc59821ee5b48f91e88e9c8111c080000dfea0bdd3adff1b8072ea45beea66b00c9cbd918a08d06950a80ea30e0d4030001a1b26740e4d3d718c06a5ed58a59ba27d29b6ef500ff000000ce000508050507070a0000002565383063303832652d646135392d346165382d383064322d3839616261393461636163620107070100000014323031392d31312d32355431333a32373a30395a07070a00000020b795e8c0c862d82136c0b23a913453fe5dcccce5161fa248c2c22209b8890f4307070100000024646e314b75746668346577744e7875394663774448667a375834535775575a645247797007070080dac40901000000244b5431485a597077756e4271554834786672646d50396d364c766852787a48327957356389799e22c430f2b24deb5d949b4f249ad1b4e0110528253faf1122a8a4f1d84dfffdcd25829cfdead36987f67c16cfcd1b92d8f91ac3e74e274c84a1d9855103"));
    let spend_tx = unwrap!(coin.search_for_swap_tx_spend_my(
        0,
        &coin.get_pubkey(),
        &[],
        &tx,
        202994,
    ).wait());
    let spend_tx = unwrap!(spend_tx);
    match spend_tx {
        FoundSwapTxSpend::Spent(spend_tx) => assert_eq!("onehiS6GMdSAwcVKnxKf2SaFUbYiuFiKVcKD1oJMzueHNVCkMtN", coin.tx_hash_to_string(&spend_tx.tx_hash())),
        FoundSwapTxSpend::Refunded(_) => panic!("Must be FoundSwapTxSpend::Spent"),
    };
}

#[test]
fn test_address_from_ec_pubkey() {
    let coin = tezos_coin_for_test();
    let fee_addr_pub_key = EcPubkey {
        curve_type: CurveType::SECP256K1,
        bytes: unwrap!(hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06")),
    };
    let address = coin.address_from_ec_pubkey(&fee_addr_pub_key).unwrap();
    assert_eq!("dn2GbmbWjNVwwBbaT8CTPjn1wyWWSsv479dZ", address.to_string());
}

#[test]
fn test_rpc_operation_result_deserialization() {
    let json_str = r#"[[{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"onxFu6P2y3tMouUEkxraFARSKaTnREVqYAhQrnEJccE8Sr87YKp","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"endorsement","level":206464,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","change":"-384000000"},{"kind":"freezer","category":"deposits","delegate":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","cycle":100,"change":"384000000"},{"kind":"freezer","category":"rewards","delegate":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","cycle":100,"change":"12000000"}],"delegate":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","slots":[27,26,20,9,3,1]}}],"signature":"sigReGF2WwQ8V2Wut7KqRWVgsFhG2YWja385snmk36m9eLfciXtKiNY49m8NnizHxV1sHaCUfKckgGvQicXTyy55YZXD656f"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"onnUHuiniVCzT7AWyzZWeg8qJipoiCVdeUn9GdTD6Hj8BxzCC3K","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"endorsement","level":206464,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","change":"-320000000"},{"kind":"freezer","category":"deposits","delegate":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","cycle":100,"change":"320000000"},{"kind":"freezer","category":"rewards","delegate":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","cycle":100,"change":"10000000"}],"delegate":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","slots":[23,22,14,8,5]}}],"signature":"sigdERynffE8dLYtUKdo8j9gzF8caL4qWMWGjaBJFx9hLqFviP6AfUnZ5sXp9sNtxmvWy21xk68MXjttza9gsmJ5jGLhjCts"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"opTKaSyYTthnEZVE2RxYwSnPQdd9eu3wrHL3GL4gJT4LF6GEZxq","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"endorsement","level":206464,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","change":"-64000000"},{"kind":"freezer","category":"deposits","delegate":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","cycle":100,"change":"64000000"},{"kind":"freezer","category":"rewards","delegate":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","cycle":100,"change":"2000000"}],"delegate":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","slots":[7]}}],"signature":"sigZZNQoi74iFvan8H9Q5apHrmXtB8cd3xhP4oBgv6KkbjUm6nHWBeqiTeDfXHnsXGLELD3jsPFiucSynnHxyypjX5qzB6Ct"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"ooP3szEoCy1uCr7qcyCEBCtT2tamhYCywdceMPytCZboPsRmSvU","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"endorsement","level":206464,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","change":"-384000000"},{"kind":"freezer","category":"deposits","delegate":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","cycle":100,"change":"384000000"},{"kind":"freezer","category":"rewards","delegate":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","cycle":100,"change":"12000000"}],"delegate":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","slots":[31,30,29,28,24,12]}}],"signature":"sigczFowuUZPHNwr3wrpyZaMB6GbFeD2GyzYy5C1zZXC983djBUcJNh3PB5Up5caE2Jy71TRqyeBXSpwRU92Jiu7UUajqUHs"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"ooUSvq7kZ7Q3rtFEdrsMyQFEd9cxmWrnmFHNUQnkup37d4tRjt9","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"endorsement","level":206464,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","change":"-896000000"},{"kind":"freezer","category":"deposits","delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","cycle":100,"change":"896000000"},{"kind":"freezer","category":"rewards","delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","cycle":100,"change":"28000000"}],"delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","slots":[25,21,19,18,17,16,15,13,11,10,6,4,2,0]}}],"signature":"sigQJdHGtkZU5uGRTV4BevMEoHhtNaxzzhH76CpRSq7BiyB1v3sCd8u17CBb32S6uata7AYQcrXgZ54LCHceoy4RFwC7fTQR"}],[],[],[{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"op5Ldqir8v8p5G4z2JasCQPVfFQM9iq6byfdAg9S4KtSPcMnSt5","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"origination","source":"dn1NxT6WVYeAqrUfKBAgfWSk5VRoSbx8z7WF","fee":"20000","counter":"436","gas_limit":"1000","storage_limit":"500","manager_pubkey":"dn1NxT6WVYeAqrUfKBAgfWSk5VRoSbx8z7WF","balance":"0","spendable":false,"delegatable":false,"script":{"code":[{"prim":"parameter","args":[{"prim":"key"}]},{"prim":"storage","args":[{"prim":"key_hash"}]},{"prim":"code","args":[[{"prim":"DUP"},{"prim":"DIP","args":[[{"prim":"CDR","annots":["@_storage_slash_1"]}]]},{"prim":"DIP","args":[[{"prim":"DROP"}]]},{"prim":"CAR","annots":["@parameter_slash_2"]},{"prim":"HASH_KEY"},{"prim":"NIL","args":[{"prim":"operation"}]},{"prim":"PAIR"}]]}],"storage":{"string":"dn1GgDxNZeGF3vr91EjrGyYrWuoX62iPvsn2"}},"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1NxT6WVYeAqrUfKBAgfWSk5VRoSbx8z7WF","change":"-20000"},{"kind":"freezer","category":"fees","delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","cycle":100,"change":"20000"}],"operation_result":{"status":"failed","errors":[{"kind":"temporary","id":"proto.004-Pt24m4xi.gas_exhausted.operation"}]}}}],"signature":"sigZp3ZsA1HLMs4UMMQ4df4EVo8tvVtiencV4tx5cxihD3ZSqQFC72j7wkFuhwudrsw9nyanjwCN6jqKAjsTXfAMaF4SSSHz"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"op6sy2ynaYJMRxdbzjkHqAy3xyWKmpysCSLDKeteb38PbWXcUWM","branch":"BLAdQgk4pJmwHGnpAEiWnrpYSFbiKvHcPL9EWLAShhkdyFzeRFW","contents":[{"kind":"transaction","source":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","fee":"100000","counter":"746","gas_limit":"800000","storage_limit":"60000","amount":"100000","destination":"KT1PKk5L9vt2RB1FcWNN1mBJQD3diafPNAD7","parameters":{"prim":"Left","args":[{"prim":"Pair","args":[{"bytes":"30633932383065622d326137342d343834352d393963352d32646262383734326239323700"},{"prim":"Pair","args":[{"string":"2019-11-26T20:33:29Z"},{"prim":"Pair","args":[{"bytes":"1a053ffe53259e6ca7a53a559c4e3d2b148df47e749190857197b916e71c3b0c"},{"string":"dn1cYshZvukj2mcpPdqqBDsyio5yWfMfdnyM"}]}]}]}]},"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","change":"-100000"},{"kind":"freezer","category":"fees","delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","cycle":100,"change":"100000"}],"operation_result":{"status":"applied","storage":{"prim":"Pair","args":[[],{"prim":"Unit"}]},"big_map_diff":[{"key_hash":"exprtZw92Udtho45LUfJxZwoqgJtGRVCigUgMt5YhgPFK2z5x7fxoy","key":{"bytes":"30633932383065622d326137342d343834352d393963352d32646262383734326239323700"},"value":{"prim":"Pair","args":[{"int":"100000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"prim":"None"},{"prim":"Pair","args":[{"int":"1574784861"},{"prim":"Pair","args":[{"int":"1574800409"},{"prim":"Pair","args":[{"bytes":"0000dfea0bdd3adff1b8072ea45beea66b00c9cbd918"},{"prim":"Pair","args":[{"bytes":"1a053ffe53259e6ca7a53a559c4e3d2b148df47e749190857197b916e71c3b0c"},{"prim":"Pair","args":[{"bytes":"00002969737230bd5ea60f632b52777981e43a25d069"},{"prim":"Pair","args":[{"prim":"None"},{"prim":"Pair","args":[{"prim":"Left","args":[{"prim":"Unit"}]},{"bytes":"30633932383065622d326137342d343834352d393963352d32646262383734326239323700"}]}]}]}]}]}]}]}]}]}]}}],"balance_updates":[{"kind":"contract","contract":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","change":"-180000"},{"kind":"contract","contract":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","change":"-100000"},{"kind":"contract","contract":"KT1PKk5L9vt2RB1FcWNN1mBJQD3diafPNAD7","change":"100000"}],"consumed_gas":"210059","storage_size":"14385","paid_storage_size_diff":"180"}}}],"signature":"sigr8A1aXQGoxuiGj9N6L9JUsLHuUcdodhhygPgNykqh1VDWZ4wYmQh7Ddqv3aZ55akdxcyphfSSB89y2gaEYrfnXu5NBQZH"}]]"#;
    let ops: Vec<Vec<OperationsResult>> = unwrap!(json::from_str(json_str));

    let json_str = r#"[[{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"ooHLZQ8gtAh8BNNKkvesjykH4rSp19Z2jXBazbbyFQFhfSYDogC","branch":"BMaA73D1hfdy5wsPZhGFyG8pez8xWNh34CVF7T3k1k3Hg9F8Kzt","contents":[{"kind":"endorsement","level":206532,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","change":"-128000000"},{"kind":"freezer","category":"deposits","delegate":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","cycle":100,"change":"128000000"},{"kind":"freezer","category":"rewards","delegate":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","cycle":100,"change":"4000000"}],"delegate":"dn1MLnf3qjGsnaStSg1jMmsdgXKz9hteWE9i","slots":[22,20]}}],"signature":"sigfVodD7NY5AEP6Gt7Jv7eeKNuud9AVv1g6xAxg6BoVivPciu2nsPXr7Lv5PBPqY5GMRkBV32y5dkHa726aPSynZd1ZNpdp"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"oohsux3n4cDarf4uQ26A1Hjp72Nu8vvy2QtUrvimK1oySWvDd3N","branch":"BMaA73D1hfdy5wsPZhGFyG8pez8xWNh34CVF7T3k1k3Hg9F8Kzt","contents":[{"kind":"endorsement","level":206532,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","change":"-128000000"},{"kind":"freezer","category":"deposits","delegate":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","cycle":100,"change":"128000000"},{"kind":"freezer","category":"rewards","delegate":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","cycle":100,"change":"4000000"}],"delegate":"dn1dXN68hzaNBVDrj2WHS2jrbWc3iamjxoaH","slots":[17,4]}}],"signature":"sigWiqsgkhJdMU3ao3DERjhYhEHcED1ecHgMt8iNTTb7S27kEJN56jahjJR5vLrUZPav4wNSMFmtD987JAS3WTAcaxfjQmFj"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"opDRfuGQ9JwNfAifni9ZeCzPgACgwJg8wGGb6gouxC6tnPAAjJm","branch":"BMaA73D1hfdy5wsPZhGFyG8pez8xWNh34CVF7T3k1k3Hg9F8Kzt","contents":[{"kind":"endorsement","level":206532,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","change":"-640000000"},{"kind":"freezer","category":"deposits","delegate":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","cycle":100,"change":"640000000"},{"kind":"freezer","category":"rewards","delegate":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","cycle":100,"change":"20000000"}],"delegate":"dn1PgwzYhTWGCzfXwRfMzRTbATUUADSq4Xgc","slots":[31,27,25,23,21,16,13,6,3,2]}}],"signature":"sigs1oXAAUDviwsY8JhttTS9kTVNwJxWKNc3Aq6s81Qdjkq479pvzSivw9dsz7CBktDNcLWn1onCFN4A8SmED1ZYFHJbxFSc"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"ooKKxJtmJ3L1xoZL3c5BK77x5W4WtsPz2wYw3VAwTpUvWgU2LNg","branch":"BMaA73D1hfdy5wsPZhGFyG8pez8xWNh34CVF7T3k1k3Hg9F8Kzt","contents":[{"kind":"endorsement","level":206532,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","change":"-320000000"},{"kind":"freezer","category":"deposits","delegate":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","cycle":100,"change":"320000000"},{"kind":"freezer","category":"rewards","delegate":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","cycle":100,"change":"10000000"}],"delegate":"dn1Yx2o6zeRHkfS6Zng25HzqD4yGkesZepGZ","slots":[29,18,11,10,9]}}],"signature":"sigfbhnnTytJTpWir5HCrXfi9ZuKCJaroviVNjCdUPehuzH6NSfX6cvUCWw7VJEKJgxNa4uQsEmfKnEXxtVfz8hw3LbdqXDP"},{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"ooSivyWDBsYgBFUWm8zJtvU5FEPUptzPgUTuZ5pJJcDHcTkZtt8","branch":"BMaA73D1hfdy5wsPZhGFyG8pez8xWNh34CVF7T3k1k3Hg9F8Kzt","contents":[{"kind":"endorsement","level":206532,"metadata":{"balance_updates":[{"kind":"contract","contract":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","change":"-832000000"},{"kind":"freezer","category":"deposits","delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","cycle":100,"change":"832000000"},{"kind":"freezer","category":"rewards","delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","cycle":100,"change":"26000000"}],"delegate":"dn1YJhqRgFWHKsaYE1JL8xyCrS8eeqXTusuu","slots":[30,28,26,24,19,15,14,12,8,7,5,1,0]}}],"signature":"sigX3Kxh9mcUdsLCYRk1WtCrpPa3ghDDe9p1DSZ8kNYi2yBzC32QvaX2dTDQpuYWShB1VfngxBLMr6gUJTASGkwhrJNF1vHB"}],[],[{"protocol":"Pt24m4xiPbLDhVgVfABUjirbmda3yohdN82Sp9FeuAXJ4eV9otd","chain_id":"NetXJr1E3KSpaPR","hash":"onrJv1dFBo8Eks8ciNLwpZ62R8c17tHwNY21tc3f4rg5jScKQR9","branch":"BMaA73D1hfdy5wsPZhGFyG8pez8xWNh34CVF7T3k1k3Hg9F8Kzt","contents":[{"kind":"activate_account","pkh":"dn1SdzZ9SkH4WddiXqRvvhWoUFX9WiVLyH8d","secret":"2cc153085b58580257a1dcea5b014cc491f9d33e","metadata":{"balance_updates":[{"kind":"contract","contract":"dn1SdzZ9SkH4WddiXqRvvhWoUFX9WiVLyH8d","change":"56678528777"}]}}],"signature":"sigddhNu7gbAkJgrULe2Wdjwxuxwp4hBUfWB7N5wE2rrncNKe9v7R7DpeqHMUu73DC1UkNwrqaYpNJgGGbQ1c9vc2c5RWG8r"}],[]]"#;
    let ops: Vec<Vec<OperationsResult>> = unwrap!(json::from_str(json_str));
}
