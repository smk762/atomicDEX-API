use super::*;
use crate::tezos::tezos_rpc::{OperationsResult, Origination};
use bitcrypto::sha256;
use common::privkey::key_pair_from_seed;

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
    let json_str = r#"{"prim":"Pair","args":[{"int":"1000000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"prim":"None"},{"prim":"Pair","args":[{"string":"2019-12-27T05:12:21Z"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"string":"tz1VuFw8bsMAfb2fKsvFvTr8qGJNJczmR3u6"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"prim":"Pair","args":[{"string":"tz1VuFw8bsMAfb2fKsvFvTr8qGJNJczmR3u6"},{"prim":"Pair","args":[{"prim":"Some","args":[{"string":"2019-12-27T05:12:26Z"}]},{"prim":"Pair","args":[{"prim":"Right","args":[{"prim":"Right","args":[{"prim":"Unit"}]}]},{"bytes":"0cccb9c14b9248d2a391262a44604ae001"}]}]}]}]}]}]}]}]}]}]}"#;
    let value: TezosValue = unwrap!(json::from_str(json_str));
    unwrap!(TezosAtomicSwap::try_from(value));
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

    let tx_hex = "153f0b9951baba428160f18453096732e426dee03651c3d63c5a6cf9ab4656dc6c00b365d13ec590bd135a6fd89eff97fe03530436f9a08d06b0d90880ea30e0d403c0843d01ee864ed14b5b3ed1b2f73e421831664bc953dfc400ff0000000085050507070a00000011f6fb2562faab4557a7bed5b0f138c38c0107070100000014313937302d30312d30315430303a30303a30305a07070a00000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550100000024747a31627a6263724c35663255356341564d67435544315637574e344c3959503668706e104decd5049f0e3e5982e0d184b094004308523e88f69242f35a63278f56dd5fb3ae29e8187639cac3849611f68fc9cbd003d04d663d8745129f454ae2a3cb04";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "242521d18d9f9f304a7aafe31774903969e8debcdbf175d58fb3ee87d3eabb416c00b365d13ec590bd135a6fd89eff97fe03530436f9a08d06b1d90880ea30e0d403c0843d01ee864ed14b5b3ed1b2f73e421831664bc953dfc400ffff0f696e69745f74657a6f735f737761700000008307070a0000001196543e4cfefd474c9a6c6f152c06c7d50107070100000014313937302d30312d30315430303a30303a30305a07070a00000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550100000024747a31627a6263724c35663255356341564d67435544315637574e344c3959503668706e6329a93d1da372dcc9da8ecebb09062b5fe19210aaaf660e43365214be06ffecc1ae1ce46dcf32cadd914887ca901677777e6a2fa86d92de7c93318edf72580c";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "cc9d74285d52af45d8c04c6f1b9eebc2ff7b0337f24db2ab24a466cb57f66be06b00467625b196495b1fd24fe5e281bad8f8bc7d3995f50904904e00007e8d56ae2e8a45f921739ee4e35acb5302988b3f3a1090418360fe638ebfceaa6c00467625b196495b1fd24fe5e281bad8f8bc7d3995a08d060580ea30e0d403c0843d01de6833e86b2e2e6d187fff8535e734affb9977cf00ffff0f696e69745f74657a6f735f737761700000008307070a00000011a4a4169861094209b50b1b479c0211fb0107070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f29250100000024747a31533462585a5848416248693654645754654e3344743958613435755643767845553c118259202dafb3ebae2cda4f005a3a2b4b6308f1d9585b94efdacfdb58f43c17136b9e352c82f25012430457bf8ecfc214a06c9c98d469d9b6d59a4d127d00";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "cc9d74285d52af45d8c04c6f1b9eebc2ff7b0337f24db2ab24a466cb57f66be06b00467625b196495b1fd24fe5e281bad8f8bc7d3995f50904904e00007e8d56ae2e8a45f921739ee4e35acb5302988b3f3a1090418360fe638ebfceaa6c00467625b196495b1fd24fe5e281bad8f8bc7d3995a08d060580ea30e0d403c0843d01de6833e86b2e2e6d187fff8535e734affb9977cf00ffff0f696e69745f74657a6f735f737761700000008307070a00000011a4a4169861094209b50b1b479c0211fb0107070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f29250100000024747a31533462585a5848416248693654645754654e3344743958613435755643767845553c118259202dafb3ebae2cda4f005a3a2b4b6308f1d9585b94efdacfdb58f43c17136b9e352c82f25012430457bf8ecfc214a06c9c98d469d9b6d59a4d127d00";
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
    let storage = unwrap!(TezosErcStorage::try_from(pair));
}

#[test]
fn deserialize_erc_account() {
    let json = r#"{"prim":"Pair","args":[{"int":"100000000"},[{"prim":"Elt","args":[{"string":"KT1A4EVVw4Jo9WvEe4KHqPYxLL6z6xs1fSAU"},{"int":"99000000"}]}]]}"#;
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
fn tezos_address_from_to_string() {
    let address = TezosAddress {
        prefix: [6, 161, 159],
        data: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU")));
}

#[test]
fn tezos_pubkey_from_to_string() {
    let pubkey = TezosPubkey {
        prefix: [13, 15, 37, 217],
        data: vec![166, 202, 119, 231, 228, 189, 30, 242, 46, 204, 159, 12, 12, 218, 180, 41, 168, 96, 249, 96, 99, 204, 81, 186, 149, 15, 209, 40, 198, 67, 175, 141],
    };

    assert_eq!(pubkey, unwrap!(TezosPubkey::from_str("edpkuugPN19icgASNMSTiVFeF4F1htia8YwA67ZANiMUEFTEzMZ4dQ")));
    assert_eq!("edpkuugPN19icgASNMSTiVFeF4F1htia8YwA67ZANiMUEFTEzMZ4dQ", pubkey.to_string());
}

#[test]
fn tezos_block_hash_from_to_string() {
    let block_hash = TezosBlockHash {
        prefix: [1, 52],
        data: H256::from([179, 210, 18, 192, 241, 185, 183, 107, 195, 238, 140, 247, 125, 33, 193, 145, 186, 39, 80, 186, 231, 132, 73, 236, 217, 134, 218, 226, 45, 91, 94, 180]),
    };

    assert_eq!("BM5UcRC5rLiajhwDNEmF3mF152f2Uiaqsj9CFTr4WyQvCsaY4pm", block_hash.to_string());
    assert_eq!(block_hash, unwrap!(TezosBlockHash::from_str("BM5UcRC5rLiajhwDNEmF3mF152f2Uiaqsj9CFTr4WyQvCsaY4pm")));
}

#[test]
fn dune_address_from_to_string() {
    let address = TezosAddress {
        prefix: [4, 177, 1],
        data: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By")));

    let address = TezosAddress {
        prefix: [4, 177, 3],
        data: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn2QkyrG831hiqQBTzdJWMbdeAhzzNcD1qE6", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn2QkyrG831hiqQBTzdJWMbdeAhzzNcD1qE6")));

    let address = TezosAddress {
        prefix: [4, 177, 6],
        data: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn3cmnob1u9F7TrUtFhZWK41TXbWmCnHRWw9", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn3cmnob1u9F7TrUtFhZWK41TXbWmCnHRWw9")));

    let address = TezosAddress {
        prefix: [2, 90, 121],
        data: H160::from([26, 143, 122, 34, 221, 133, 45, 28, 133, 66, 215, 149, 234, 227, 176, 148, 167, 198, 41, 170]),
    };

    assert_eq!(address, unwrap!(TezosAddress::from_str("KT1B1D1iVrVyrABRRp6PxPU894dzWghvt4mf")));
    assert_eq!("KT1B1D1iVrVyrABRRp6PxPU894dzWghvt4mf", address.to_string());
}

#[test]
fn tezos_secret_from_to_string() {
    let secret = TezosSecret {
        prefix: ED_SK_PREFIX,
        data: vec![197, 109, 203, 119, 241, 255, 240, 13, 26, 31, 83, 48, 167, 122, 159, 31, 49, 207, 112, 250, 122, 214, 145, 162, 43, 94, 194, 140, 219, 35, 35, 80],
    };

    assert_eq!(secret, unwrap!(TezosSecret::from_str("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ")));
    assert_eq!("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ", secret.to_string());

    let secret = EcPrivkey::new(CurveType::ED25519, &secret.data).unwrap();
    let pubkey = secret.get_pubkey();
    let tezos_pub = TezosPubkey {
        prefix: ED_PK_PREFIX,
        data: pubkey.bytes.clone(),
    };

    log!((tezos_pub));
    log!((address_from_ec_pubkey(TZ1_ADDR_PREFIX, &pubkey)));

    let secret = TezosSecret {
        prefix: [43, 246, 78, 7],
        data: vec![61, 201, 24, 121, 54, 228, 191, 64, 218, 241, 174, 189, 244, 197, 139, 124, 185, 102, 81, 2, 192, 54, 64, 185, 214, 150, 162, 96, 216, 123, 29, 165, 142, 161, 192, 170, 205, 174, 219, 163, 231, 121, 0, 121, 201, 83, 211, 80, 128, 182, 202, 191, 220, 249, 57, 121, 194, 72, 41, 174, 166, 58, 21, 17],
    };

    assert_eq!(secret, unwrap!(TezosSecret::from_str("edskRk6cFnKSme2QuwCA3pCtqQYujU2P1mUWzFeDswm776jqMio7W2eYwV62y2nXfRhvqFw48H7Sf8Q24F2n8RuqCBXBdKxFCs")));
    assert_eq!("edskRk6cFnKSme2QuwCA3pCtqQYujU2P1mUWzFeDswm776jqMio7W2eYwV62y2nXfRhvqFw48H7Sf8Q24F2n8RuqCBXBdKxFCs", secret.to_string());

    let secret = TezosSecret {
        prefix: ED_SK_PREFIX,
        data: vec![61, 201, 24, 121, 54, 228, 191, 64, 218, 241, 174, 189, 244, 197, 139, 124, 185, 102, 81, 2, 192, 54, 64, 185, 214, 150, 162, 96, 216, 123, 29, 165],
    };

    assert_eq!("edsk397WR2NimQ6WxgjQiPPkfJFC1YqM2RqA3sVhHuXtTvr2YGmQ5x", secret.to_string());
    assert_eq!(secret, unwrap!(TezosSecret::from_str("edsk397WR2NimQ6WxgjQiPPkfJFC1YqM2RqA3sVhHuXtTvr2YGmQ5x")));
}

#[test]
fn test_address_from_ec_pubkey() {
    let coin = tezos_coin_for_test(
        &hex::decode("809465b17d0a4ddb3e4c69e8f23c2cabad868f51f8bed5c765ad1d6516c3306f").unwrap(),
        "https://tezos-dev.cryptonomic-infra.tech",
        "KT1XcWHaTLiGpUVTHDLguus9rtV2ryhMtXxH",
    );
    let fee_addr_pub_key = EcPubkey {
        curve_type: CurveType::SECP256K1,
        bytes: unwrap!(hex::decode("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06")),
    };
    let address = coin.address_from_ec_pubkey(&fee_addr_pub_key).unwrap();
    assert_eq!("tz2L6seff8XKa64L4bmjL3ePt1zFdMrry63B", address.to_string());
}

#[test]
fn test_rpc_operation_result_deserialization() {
    let json_str = r#"[[{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"opM88QgFAoQmjqq25d4Um3Myb9hn5tByhewhPFia8QLzFAJa8pU","branch":"BKkr44BYJQ4UdrUYzrMUfLYZm5fPefhgaJMNKyw4xFL2ufRtV7Q","contents":[{"kind":"endorsement","level":128918,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","change":"-62000000"},{"kind":"freezer","category":"deposits","delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","cycle":62,"change":"62000000"},{"kind":"freezer","category":"rewards","delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","cycle":62,"change":"333333"}],"delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","slots":[20]}}],"signature":"sigtuPkohuGNeJJsHEikjVQ8PViguDtKsahNiLCGzqLrEoU4GDVCu4TfpDRTD6zFVHPuEPH7nwr2AWNFC9z8YDfrGsivAUty"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"ooUwDyAj5SqDS1FTAqiE3YMxE9TwxFxfXMB5HrcFxB4g46t3rjX","branch":"BKkr44BYJQ4UdrUYzrMUfLYZm5fPefhgaJMNKyw4xFL2ufRtV7Q","contents":[{"kind":"endorsement","level":128918,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","change":"-186000000"},{"kind":"freezer","category":"deposits","delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","cycle":62,"change":"186000000"},{"kind":"freezer","category":"rewards","delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","cycle":62,"change":"999999"}],"delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","slots":[29,27,7]}}],"signature":"sigWnpKZyZ9mbxmMZXTPGesh89KaTDS2wmFgqJVxoC9pmsXCrtLxxvbM7agRvPwxA1sGQLt9x5VyVsXoUHz1Vg8QPq9txayB"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"ooSc68Pi1UZLYGs6ue2PFVuMF9q2ttJ9fUWqsfQUKUztuKQtQdn","branch":"BKkr44BYJQ4UdrUYzrMUfLYZm5fPefhgaJMNKyw4xFL2ufRtV7Q","contents":[{"kind":"endorsement","level":128918,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","change":"-124000000"},{"kind":"freezer","category":"deposits","delegate":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","cycle":62,"change":"124000000"},{"kind":"freezer","category":"rewards","delegate":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","cycle":62,"change":"666666"}],"delegate":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","slots":[28,25]}}],"signature":"sigPsPyLPfMJuGrQat69sHCEf2PtDUMKboTyyC9EJCnqhujwA8hZoAV9MGV9rEhyhPsKizQ42J7wDUYVsed9C35XtAsH9wMg"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"oomYXFPGiTLN2HpiUxPMjXHTHf62gqFR6k3cFNQrgmnixSATZwA","branch":"BKkr44BYJQ4UdrUYzrMUfLYZm5fPefhgaJMNKyw4xFL2ufRtV7Q","contents":[{"kind":"endorsement","level":128918,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","change":"-248000000"},{"kind":"freezer","category":"deposits","delegate":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","cycle":62,"change":"248000000"},{"kind":"freezer","category":"rewards","delegate":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","cycle":62,"change":"1333332"}],"delegate":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","slots":[31,24,17,6]}}],"signature":"sigiqLa44xzJaqRe6NFfHULiUCfDaczeoKWQxDfhK39dXjVd6JMAM5V4N97LEzQFFSfuKbpnE2UEt5zhhSKgkRwSMAwVvjbV"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"opDcpYQ7jkT7mn4gjXCrm39PA2TnUX7jc13o43wKKzxiTtsQp5P","branch":"BKkr44BYJQ4UdrUYzrMUfLYZm5fPefhgaJMNKyw4xFL2ufRtV7Q","contents":[{"kind":"endorsement","level":128918,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","change":"-310000000"},{"kind":"freezer","category":"deposits","delegate":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","cycle":62,"change":"310000000"},{"kind":"freezer","category":"rewards","delegate":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","cycle":62,"change":"1666665"}],"delegate":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","slots":[18,10,8,3,2]}}],"signature":"sigvEhkXvGaCtVdd8EhH3TesoyLP6HwXsnaRbBaB7HJxwm3E9gHZ7JrLJYkntVujAqHkcK1Vs5zUsXMvr6U72KZBciVWquHS"}],[],[],[{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"ooLhaAxdCdDKtEXJrmmnTamgLjuCxKkrcPbkV3MKmKH5zzHj9Kf","branch":"BKkr44BYJQ4UdrUYzrMUfLYZm5fPefhgaJMNKyw4xFL2ufRtV7Q","contents":[{"kind":"transaction","source":"tz1bzbcrL5f2U5cAVMgCUD1V7WN4L9YP6hpn","fee":"100000","counter":"142504","gas_limit":"800000","storage_limit":"60000","amount":"1000000","destination":"KT1KSSmZoSyiBsxsQKCbNxtTYHyoUNYybHC3","parameters":{"entrypoint":"init_tezos_swap","value":{"prim":"Pair","args":[{"bytes":"774b5a2833b24e4f99ecfdb00951fc8201"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"bytes":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},{"string":"dn1YVVZhQKdeqB9Qst6vXu97BTtK9fZiC2Gt"}]}]}]}},"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1bzbcrL5f2U5cAVMgCUD1V7WN4L9YP6hpn","change":"-100000"},{"kind":"freezer","category":"fees","delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","cycle":62,"change":"100000"}],"operation_result":{"status":"failed","errors":[{"kind":"permanent","id":"proto.005-PsBabyM1.michelson_v1.bad_contract_parameter","contract":"KT1KSSmZoSyiBsxsQKCbNxtTYHyoUNYybHC3"},{"kind":"permanent","id":"proto.005-PsBabyM1.invalidSyntacticConstantError","location":0,"expectedForm":{"prim":"or","args":[{"prim":"pair","args":[{"prim":"bytes"},{"prim":"pair","args":[{"prim":"timestamp"},{"prim":"pair","args":[{"prim":"bytes"},{"prim":"address"}]}]}],"annots":["%init_tezos_swap"]},{"prim":"or","args":[{"prim":"pair","args":[{"prim":"bytes"},{"prim":"pair","args":[{"prim":"timestamp"},{"prim":"pair","args":[{"prim":"bytes"},{"prim":"pair","args":[{"prim":"address"},{"prim":"pair","args":[{"prim":"nat"},{"prim":"address"}]}]}]}]}],"annots":["%init_erc_swap"]},{"prim":"or","args":[{"prim":"pair","args":[{"prim":"bytes"},{"prim":"pair","args":[{"prim":"bytes"},{"prim":"key_hash"}]}],"annots":["%receiver_spends"]},{"prim":"pair","args":[{"prim":"bytes"},{"prim":"key_hash"}],"annots":["%sender_refunds"]}]}]}]},"wrongExpression":{"prim":"Left","args":[{"prim":"Pair","args":[{"bytes":"774b5a2833b24e4f99ecfdb00951fc8201"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"bytes":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},{"string":"dn1YVVZhQKdeqB9Qst6vXu97BTtK9fZiC2Gt"}]}]}]}]}},{"kind":"permanent","id":"proto.005-PsBabyM1.contract.invalid_contract_notation","notation":"dn1YVVZhQKdeqB9Qst6vXu97BTtK9fZiC2Gt"}]}}}],"signature":"sigchy4gKJSC8v1dXWcyCzaemTWR9DVKxdWvwpUutgStA62nUck8maMn46kxF63W2Sxt7Rh142S5EGmvnxNi5aaWS4T5NEs7"}]]"#;
    let ops: Vec<Vec<OperationsResult>> = unwrap!(json::from_str(json_str));

    let json_str = r#"[[{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"ooneMXDoxXKn3uwKhaUJ7ZsD3EJhkLLSNTywEfL3HDp35qgJbMk","branch":"BKtrkceGv2tSLGvo57YWUM6Wwfugwg7Ahf2dmW2hc4y4uSLawm7","contents":[{"kind":"endorsement","level":128932,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","change":"-186000000"},{"kind":"freezer","category":"deposits","delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","cycle":62,"change":"186000000"},{"kind":"freezer","category":"rewards","delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","cycle":62,"change":"3000000"}],"delegate":"tz1hZYjNoeeHmGZbwuspzacBzvhoyToC3ZvM","slots":[7,4,0]}}],"signature":"sigbGsUQEGq6Zxvj7vt8nTwkLCuH5jhhiBWwYegYPbEhYsAH25PyupiovogNaeZRhcxxJW5SHFpBVKbCcjdPBvwjS9vrUXFS"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"ontzXgjtJC84JiQY1nMxbrg3ycowoh5w9LVYh5YBXiwD7zDMZtd","branch":"BKtrkceGv2tSLGvo57YWUM6Wwfugwg7Ahf2dmW2hc4y4uSLawm7","contents":[{"kind":"endorsement","level":128932,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","change":"-62000000"},{"kind":"freezer","category":"deposits","delegate":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","cycle":62,"change":"62000000"},{"kind":"freezer","category":"rewards","delegate":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","cycle":62,"change":"1000000"}],"delegate":"tz1a6SkBrxCywRHHsUKN3uQse7huiBNSGb5p","slots":[31]}}],"signature":"siguDrJykNKjgcCTHGSfWfUt7zHE4kuVKmDdVir8TLKsYxWjQDVeceEK1FSkguxWkaV8so8aJnua6MPFkHBAXkEfGBFh5YA5"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"opS9FxQxSkKwu4VenjxbBBFnLnKYEQ5kj6Zd3T27FJFimsgM51v","branch":"BKtrkceGv2tSLGvo57YWUM6Wwfugwg7Ahf2dmW2hc4y4uSLawm7","contents":[{"kind":"endorsement","level":128932,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","change":"-248000000"},{"kind":"freezer","category":"deposits","delegate":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","cycle":62,"change":"248000000"},{"kind":"freezer","category":"rewards","delegate":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","cycle":62,"change":"4000000"}],"delegate":"tz3WXYtyDUNL91qfiCJtVUX746QpNv5i5ve5","slots":[28,20,18,17]}}],"signature":"sigTa4nfJ78JQFR2e7QDAbg5qCK24kEtSqyjcm9MjvUcbb9tMyZKaX1V5zfvwCFkybfrfX4xahKF5DGRdqDKF33NMtEDSdHm"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"oozGAM8C5ZGwackjNuGQCyUfDCVC95HKryJ3i9MXRMyt5LFveYN","branch":"BKtrkceGv2tSLGvo57YWUM6Wwfugwg7Ahf2dmW2hc4y4uSLawm7","contents":[{"kind":"endorsement","level":128932,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","change":"-62000000"},{"kind":"freezer","category":"deposits","delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","cycle":62,"change":"62000000"},{"kind":"freezer","category":"rewards","delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","cycle":62,"change":"1000000"}],"delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","slots":[10]}}],"signature":"signPrwnDyRc9ULv5xXY35t3qmkjVXUzYhkezPMiytimMe5mpdKS8rUjjmSFcXb6q6kSoL2GCedL2itnrLsPrGu7NF84SUeg"},{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"oofyT2idQQVJ94E8CjjvLPmvoHmwJR3ri41d55BSv9sjSSvunxi","branch":"BKtrkceGv2tSLGvo57YWUM6Wwfugwg7Ahf2dmW2hc4y4uSLawm7","contents":[{"kind":"endorsement","level":128932,"metadata":{"balance_updates":[{"kind":"contract","contract":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","change":"-434000000"},{"kind":"freezer","category":"deposits","delegate":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","cycle":62,"change":"434000000"},{"kind":"freezer","category":"rewards","delegate":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","cycle":62,"change":"7000000"}],"delegate":"tz1PirboZKFVqkfE45hVLpkpXaZtLk3mqC17","slots":[27,25,24,19,5,3,2]}}],"signature":"sigd4muEFFugo3RYud4CtkWibzuFEC62Lr1TjVDqtFVKk9GqwFG6nuDYtZdXqTnvGjveMTzU1bUEFTdR6t9gAd9KKga4UVVU"}],[],[],[{"protocol":"PsBabyM1eUXZseaJdmXFApDSBqj8YBfwELoxZHHW77EMcAbbwAS","chain_id":"NetXUdfLh6Gm88t","hash":"ones9yKL2tKpZUisDyaozV3J3FhNRQ86vG3N4dQK748UzW43LKA","branch":"BKtrkceGv2tSLGvo57YWUM6Wwfugwg7Ahf2dmW2hc4y4uSLawm7","contents":[{"kind":"reveal","source":"tz1ckTtPKovP8y6UsxeX2de2KtZp7273brjJ","fee":"1269","counter":"142966","gas_limit":"10000","storage_limit":"0","public_key":"edpktfGPHV7UCGdiB1onLmMiVpPF8gmyno9DLrXyUEgM6yh8t6M16q","metadata":{"balance_updates":[{"kind":"contract","contract":"tz1ckTtPKovP8y6UsxeX2de2KtZp7273brjJ","change":"-1269"},{"kind":"freezer","category":"fees","delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","cycle":62,"change":"1269"}],"operation_result":{"status":"applied","consumed_gas":"10000"}}},{"kind":"transaction","source":"tz1ckTtPKovP8y6UsxeX2de2KtZp7273brjJ","fee":"1275","counter":"142967","gas_limit":"10600","storage_limit":"300","amount":"124997456","destination":"tz1Kqt9BkG9uoazs66aKbsaLTYnGAcyXcZQh","metadata":{"balance_updates":[{"kind":"contract","contract":"tz1ckTtPKovP8y6UsxeX2de2KtZp7273brjJ","change":"-1275"},{"kind":"freezer","category":"fees","delegate":"tz1fyYJwgV1ozj6RyjtU1hLTBeoqQvQmRjVv","cycle":62,"change":"1275"}],"operation_result":{"status":"applied","balance_updates":[{"kind":"contract","contract":"tz1ckTtPKovP8y6UsxeX2de2KtZp7273brjJ","change":"-124997456"},{"kind":"contract","contract":"tz1Kqt9BkG9uoazs66aKbsaLTYnGAcyXcZQh","change":"124997456"}],"consumed_gas":"10209"}}}],"signature":"sigXovnjn5UpXc5fdt3X5d6A1zdY7LLXVkXaBpTwUbYLKbtCXsfgKySQLfBq9ZEpZ2d2C7PFoM1P9fLGNfWqwXRHuBNuARFy"}]]"#;
    let _ops: Vec<Vec<OperationsResult>> = unwrap!(json::from_str(json_str));
}

#[test]
fn test_coin_from_conf_and_request() {
    let req = json!({
        "method": "enable",
        "coin": "TEZOS",
        "urls": [
            "https://tezos-dev.cryptonomic-infra.tech"
        ],
        "swap_contract_address": "KT1NeiPn2baKGyofShT4B4NzVnXomgSLj6UK",
        "mm2":1
    });
    let priv_key = hex::decode("3dc9187936e4bf40daf1aebdf4c58b7cb9665102c03640b9d696a260d87b1da5").unwrap();
    let coin = block_on(tezos_coin_from_conf_and_request("TEZOS", &COMMON_XTZ_CONFIG, &req, &priv_key)).unwrap();
    assert_eq!(TZ1_ADDR_PREFIX, coin.addr_prefixes.ed25519);
    assert_eq!(TZ2_ADDR_PREFIX, coin.addr_prefixes.secp256k1);
    assert_eq!(TZ3_ADDR_PREFIX, coin.addr_prefixes.p256);
    assert_eq!("KT1NeiPn2baKGyofShT4B4NzVnXomgSLj6UK", coin.swap_contract_address.to_string());
}
