use common::now_sec;
use compact_uuid::CompactUuid;
use mm2_number::{BigRational, MmNumber};
use mm2_rpc::data::legacy::{MatchBy as SuperMatchBy, OrderConfirmationsSettings, TakerAction};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use crate::mm2::lp_ordermatch::{AlbOrderedOrderbookPair, H64};

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum OrdermatchMessage {
    MakerOrderCreated(MakerOrderCreated),
    MakerOrderUpdated(MakerOrderUpdated),
    PubkeyKeepAlive(PubkeyKeepAlive),
    MakerOrderCancelled(MakerOrderCancelled),
    TakerRequest(TakerRequest),
    MakerReserved(MakerReserved),
    TakerConnect(TakerConnect),
    MakerConnected(MakerConnected),
}

impl From<PubkeyKeepAlive> for OrdermatchMessage {
    fn from(keep_alive: PubkeyKeepAlive) -> Self { OrdermatchMessage::PubkeyKeepAlive(keep_alive) }
}

impl From<MakerOrderUpdated> for OrdermatchMessage {
    fn from(message: MakerOrderUpdated) -> Self { OrdermatchMessage::MakerOrderUpdated(message) }
}

/// MsgPack compact representation does not work with tagged enums (encoding works, but decoding fails)
/// This is untagged representation also using compact Uuid representation
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MatchBy {
    Any,
    Orders(HashSet<CompactUuid>),
    Pubkeys(HashSet<[u8; 32]>),
}

impl From<SuperMatchBy> for MatchBy {
    fn from(match_by: SuperMatchBy) -> MatchBy {
        match match_by {
            SuperMatchBy::Any => MatchBy::Any,
            SuperMatchBy::Orders(uuids) => MatchBy::Orders(uuids.into_iter().map(|uuid| uuid.into()).collect()),
            SuperMatchBy::Pubkeys(pubkeys) => MatchBy::Pubkeys(pubkeys.into_iter().map(|pubkey| pubkey.0).collect()),
        }
    }
}

impl From<MatchBy> for SuperMatchBy {
    fn from(match_by: MatchBy) -> Self {
        match match_by {
            MatchBy::Any => SuperMatchBy::Any,
            MatchBy::Orders(uuids) => SuperMatchBy::Orders(uuids.into_iter().map(|uuid| uuid.into()).collect()),
            MatchBy::Pubkeys(pubkeys) => {
                SuperMatchBy::Pubkeys(pubkeys.into_iter().map(|pubkey| pubkey.into()).collect())
            },
        }
    }
}

mod compact_uuid {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::str::FromStr;
    use uuid::Uuid;

    /// Default MsgPack encoded UUID length is 38 bytes (seems like it is encoded as string)
    /// This wrapper is encoded to raw 16 bytes representation
    /// Derives all traits of wrapped value
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct CompactUuid(Uuid);

    impl From<Uuid> for CompactUuid {
        fn from(uuid: Uuid) -> Self { CompactUuid(uuid) }
    }

    impl From<CompactUuid> for Uuid {
        fn from(compact: CompactUuid) -> Self { compact.0 }
    }

    impl FromStr for CompactUuid {
        type Err = uuid::Error;

        fn from_str(str: &str) -> Result<Self, Self::Err> {
            let uuid = Uuid::parse_str(str)?;
            Ok(uuid.into())
        }
    }

    impl Serialize for CompactUuid {
        fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            s.serialize_bytes(self.0.as_bytes())
        }
    }

    impl<'de> Deserialize<'de> for CompactUuid {
        fn deserialize<D>(d: D) -> Result<CompactUuid, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: &[u8] = Deserialize::deserialize(d)?;
            let uuid = Uuid::from_slice(bytes)
                .map_err(|e| serde::de::Error::custom(format!("Uuid::from_slice error {}", e)))?;
            Ok(uuid.into())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MakerOrderCreated {
    pub uuid: CompactUuid,
    pub base: String,
    pub rel: String,
    pub price: BigRational,
    pub max_volume: BigRational,
    pub min_volume: BigRational,
    /// This is timestamp of order creation
    pub created_at: u64,
    pub conf_settings: OrderConfirmationsSettings,
    /// This is timestamp of message
    pub timestamp: u64,
    pub pair_trie_root: H64,
    #[serde(default)]
    pub base_protocol_info: Vec<u8>,
    #[serde(default)]
    pub rel_protocol_info: Vec<u8>,
}

#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct PubkeyKeepAlive {
    pub trie_roots: HashMap<AlbOrderedOrderbookPair, H64>,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MakerOrderCancelled {
    pub uuid: CompactUuid,
    pub timestamp: u64,
    pub pair_trie_root: H64,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub struct MakerOrderUpdatedV1 {
    uuid: CompactUuid,
    pub new_price: Option<BigRational>,
    pub new_max_volume: Option<BigRational>,
    pub new_min_volume: Option<BigRational>,
    timestamp: u64,
    pair_trie_root: H64,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub struct MakerOrderUpdatedV2 {
    uuid: CompactUuid,
    pub new_price: Option<BigRational>,
    pub new_max_volume: Option<BigRational>,
    pub new_min_volume: Option<BigRational>,
    timestamp: u64,
    pair_trie_root: H64,
    pub conf_settings: Option<OrderConfirmationsSettings>,
}

#[derive(Clone, Debug, Eq, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MakerOrderUpdated {
    V1(MakerOrderUpdatedV1),
    V2(MakerOrderUpdatedV2),
}

impl MakerOrderUpdated {
    pub fn new(uuid: Uuid) -> Self {
        MakerOrderUpdated::V2(MakerOrderUpdatedV2 {
            uuid: uuid.into(),
            new_price: None,
            new_max_volume: None,
            new_min_volume: None,
            conf_settings: None,
            timestamp: now_sec(),
            pair_trie_root: H64::default(),
        })
    }

    pub fn with_new_price(&mut self, new_price: BigRational) {
        match self {
            MakerOrderUpdated::V1(v1) => v1.new_price = Some(new_price),
            MakerOrderUpdated::V2(v2) => v2.new_price = Some(new_price),
        }
    }

    pub fn with_new_max_volume(&mut self, new_max_volume: BigRational) {
        match self {
            MakerOrderUpdated::V1(v1) => v1.new_max_volume = Some(new_max_volume),
            MakerOrderUpdated::V2(v2) => v2.new_max_volume = Some(new_max_volume),
        }
    }

    pub fn with_new_min_volume(&mut self, new_min_volume: BigRational) {
        match self {
            MakerOrderUpdated::V1(v1) => v1.new_min_volume = Some(new_min_volume),
            MakerOrderUpdated::V2(v2) => v2.new_min_volume = Some(new_min_volume),
        }
    }

    pub fn with_new_conf_settings(&mut self, conf_settings: OrderConfirmationsSettings) {
        match self {
            MakerOrderUpdated::V1(_) => {},
            MakerOrderUpdated::V2(v2) => {
                v2.conf_settings = Some(conf_settings);
            },
        }
    }

    pub fn new_price(&self) -> Option<MmNumber> {
        match self {
            MakerOrderUpdated::V1(v1) => v1.new_price.as_ref().map(|num| num.clone().into()),
            MakerOrderUpdated::V2(v2) => v2.new_price.as_ref().map(|num| num.clone().into()),
        }
    }

    pub fn new_max_volume(&self) -> Option<MmNumber> {
        match self {
            MakerOrderUpdated::V1(v1) => v1.new_max_volume.as_ref().map(|num| num.clone().into()),
            MakerOrderUpdated::V2(v2) => v2.new_max_volume.as_ref().map(|num| num.clone().into()),
        }
    }

    pub fn new_min_volume(&self) -> Option<MmNumber> {
        match self {
            MakerOrderUpdated::V1(v1) => v1.new_min_volume.as_ref().map(|num| num.clone().into()),
            MakerOrderUpdated::V2(v2) => v2.new_min_volume.as_ref().map(|num| num.clone().into()),
        }
    }

    pub fn new_conf_settings(&self) -> Option<OrderConfirmationsSettings> {
        match self {
            MakerOrderUpdated::V1(_) => None,
            MakerOrderUpdated::V2(v2) => v2.conf_settings.clone(),
        }
    }

    pub fn uuid(&self) -> Uuid {
        match self {
            MakerOrderUpdated::V1(v1) => v1.uuid.into(),
            MakerOrderUpdated::V2(v2) => v2.uuid.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TakerRequest {
    pub base: String,
    pub rel: String,
    pub base_amount: BigRational,
    pub rel_amount: BigRational,
    pub action: TakerAction,
    pub uuid: CompactUuid,
    pub match_by: MatchBy,
    pub conf_settings: OrderConfirmationsSettings,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_protocol_info: Option<Vec<u8>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel_protocol_info: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MakerReserved {
    pub base: String,
    pub rel: String,
    pub base_amount: BigRational,
    pub rel_amount: BigRational,
    pub taker_order_uuid: CompactUuid,
    pub maker_order_uuid: CompactUuid,
    pub conf_settings: OrderConfirmationsSettings,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_protocol_info: Option<Vec<u8>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel_protocol_info: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TakerConnect {
    pub taker_order_uuid: CompactUuid,
    pub maker_order_uuid: CompactUuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MakerConnected {
    pub taker_order_uuid: CompactUuid,
    pub maker_order_uuid: CompactUuid,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod new_protocol_tests {
    use common::new_uuid;

    use super::*;

    #[test]
    fn check_maker_order_updated_serde() {
        let uuid = CompactUuid::from(new_uuid());
        let timestamp = now_sec();
        let conf_settings = Some(OrderConfirmationsSettings {
            base_confs: 5,
            base_nota: true,
            rel_confs: 5,
            rel_nota: true,
        });
        // old format should be deserialized to MakerOrderUpdated::V1
        let v1 = MakerOrderUpdatedV1 {
            uuid,
            new_price: Some(BigRational::from_integer(2.into())),
            new_max_volume: Some(BigRational::from_integer(3.into())),
            new_min_volume: Some(BigRational::from_integer(1.into())),
            timestamp,
            pair_trie_root: H64::default(),
        };

        let expected = MakerOrderUpdated::V1(MakerOrderUpdatedV1 {
            uuid,
            new_price: Some(BigRational::from_integer(2.into())),
            new_max_volume: Some(BigRational::from_integer(3.into())),
            new_min_volume: Some(BigRational::from_integer(1.into())),
            timestamp,
            pair_trie_root: H64::default(),
        });

        let serialized = rmp_serde::to_vec_named(&v1).unwrap();

        let deserialized: MakerOrderUpdated = rmp_serde::from_slice(serialized.as_slice()).unwrap();

        assert_eq!(deserialized, expected);

        // new format should be deserialized to old
        let v2 = MakerOrderUpdated::V2(MakerOrderUpdatedV2 {
            uuid,
            new_price: Some(BigRational::from_integer(2.into())),
            new_max_volume: Some(BigRational::from_integer(3.into())),
            new_min_volume: Some(BigRational::from_integer(1.into())),
            timestamp,
            pair_trie_root: H64::default(),
            conf_settings: conf_settings.clone(),
        });

        let expected = MakerOrderUpdatedV1 {
            uuid,
            new_price: Some(BigRational::from_integer(2.into())),
            new_max_volume: Some(BigRational::from_integer(3.into())),
            new_min_volume: Some(BigRational::from_integer(1.into())),
            timestamp,
            pair_trie_root: H64::default(),
        };

        let serialized = rmp_serde::to_vec_named(&v2).unwrap();

        let deserialized: MakerOrderUpdatedV1 = rmp_serde::from_slice(serialized.as_slice()).unwrap();

        assert_eq!(deserialized, expected);

        // new format should be deserialized to new
        let v2 = MakerOrderUpdated::V2(MakerOrderUpdatedV2 {
            uuid,
            new_price: Some(BigRational::from_integer(2.into())),
            new_max_volume: Some(BigRational::from_integer(3.into())),
            new_min_volume: Some(BigRational::from_integer(1.into())),
            timestamp,
            pair_trie_root: H64::default(),
            conf_settings,
        });

        let serialized = rmp_serde::to_vec(&v2).unwrap();

        let deserialized: MakerOrderUpdated = rmp_serde::from_slice(serialized.as_slice()).unwrap();

        assert_eq!(deserialized, v2);
    }

    #[test]
    fn test_maker_order_created_serde() {
        #[derive(Clone, Debug, Eq, Deserialize, PartialEq, Serialize)]
        struct MakerOrderCreatedV1 {
            pub uuid: CompactUuid,
            pub base: String,
            pub rel: String,
            pub price: BigRational,
            pub max_volume: BigRational,
            pub min_volume: BigRational,
            /// This is timestamp of order creation
            pub created_at: u64,
            pub conf_settings: OrderConfirmationsSettings,
            /// This is timestamp of message
            pub timestamp: u64,
            pub pair_trie_root: H64,
        }

        let old_msg = MakerOrderCreatedV1 {
            uuid: new_uuid().into(),
            base: "RICK".to_string(),
            rel: "MORTY".to_string(),
            price: BigRational::from_integer(1.into()),
            max_volume: BigRational::from_integer(2.into()),
            min_volume: BigRational::from_integer(1.into()),
            created_at: 0,
            conf_settings: Default::default(),
            timestamp: 0,
            pair_trie_root: H64::default(),
        };

        let old_serialized = rmp_serde::to_vec_named(&old_msg).unwrap();

        let mut new: MakerOrderCreated = rmp_serde::from_slice(&old_serialized).unwrap();

        new.base_protocol_info = vec![1, 2, 3];
        new.rel_protocol_info = vec![1, 2, 3, 4];

        let new_serialized = rmp_serde::to_vec_named(&new).unwrap();
        let _old_from_new: MakerOrderCreatedV1 = rmp_serde::from_slice(&new_serialized).unwrap();
    }
}
