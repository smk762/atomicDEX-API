use ed25519_dalek::{Keypair as EdKeypair, PublicKey as EdPublicKey, SecretKey as EdSecret,
                    Signature as EdSignature};
use secp256k1::{Message as SecpMessage, PublicKey as SecpPublicKey, SecretKey as SecpSecret,
                sign as secp_sign, Signature as SecpSignature, verify as secp_verify_sig};
use serialization::{Deserializable, deserialize, Reader, Serializable, serialize, Stream};
use serde::{Serialize, Serializer, Deserialize};
use serde::de::{Deserializer, Visitor};
use sha2::{Sha512};

pub trait CryptoOps {
    fn get_pubkey(&self) -> Result<EcPubkey, String>;

    fn sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurveType {
    SECP256K1,
    ED25519,
    P256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcPrivkey {
    curve_type: CurveType,
    bytes: Vec<u8>,
}

impl EcPrivkey {
    pub fn new(curve_type: CurveType, bytes: Vec<u8>) -> EcPrivkey {
        EcPrivkey {
            curve_type,
            bytes,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn get_pubkey(&self) -> Result<EcPubkey, String> {
        match self.curve_type {
            CurveType::ED25519 => {
                let secret = try_s!(EdSecret::from_bytes(&self.bytes));
                let public = EdPublicKey::from_secret::<Sha512>(&secret);
                Ok(EcPubkey {
                    curve_type: CurveType::ED25519,
                    bytes: public.as_bytes().to_vec()
                })
            },
            CurveType::SECP256K1 => {
                let secret = try_s!(SecpSecret::parse_slice(&self.bytes).map_err(|e| ERRL!("{:?}", e)));
                let public = SecpPublicKey::from_secret_key(&secret);
                Ok(EcPubkey {
                    curve_type: CurveType::SECP256K1,
                    bytes: public.serialize_compressed().to_vec(),
                })
            },
            _ => unimplemented!(),
        }
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        match self.curve_type {
            CurveType::ED25519 => {
                let secret = try_s!(EdSecret::from_bytes(&self.bytes));
                let public = EdPublicKey::from_secret::<Sha512>(&secret);
                let mut bytes = vec![];
                bytes.extend_from_slice(secret.as_bytes());
                bytes.extend_from_slice(public.as_bytes());
                let key_pair = try_s!(EdKeypair::from_bytes(&bytes));
                Ok(key_pair.sign::<Sha512>(msg).to_bytes().to_vec())
            },
            CurveType::SECP256K1 => {
                let secret = try_s!(SecpSecret::parse_slice(&self.bytes).map_err(|e| ERRL!("{:?}", e)));
                let msg = try_s!(SecpMessage::parse_slice(msg).map_err(|e| ERRL!("{:?}", e)));
                secp_sign(&msg, &secret).map(|(sig, _)| sig.serialize().to_vec()).map_err(|e| ERRL!("{:?}", e))
            },
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcPubkey {
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

impl EcPubkey {
    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> Result<bool, String> {
        match self.curve_type {
            CurveType::ED25519 => {
                let public = try_s!(EdPublicKey::from_bytes(&self.bytes));
                let sig = try_s!(EdSignature::from_bytes(sig));
                public.verify::<Sha512>(msg, &sig).map(|_| true).map_err(|e| ERRL!("{}", e))
            },
            CurveType::SECP256K1 => {
                let public = try_s!(SecpPublicKey::parse_slice(&self.bytes, None).map_err(|e| ERRL!("{:?}", e)));
                let sig = try_s!(SecpSignature::parse_slice(sig).map_err(|e| ERRL!("{:?}", e)));
                let msg = try_s!(SecpMessage::parse_slice(msg).map_err(|e| ERRL!("{:?}", e)));
                Ok(secp_verify_sig(&msg, &sig, &public))
            },
            CurveType::P256 => unimplemented!(),
        }
    }
}

impl Default for EcPubkey {
    fn default() -> EcPubkey {
        EcPubkey {
            curve_type: CurveType::SECP256K1,
            bytes: vec![],
        }
    }
}

impl Serializable for EcPubkey {
    fn serialize(&self, s: &mut Stream) {
        let tag: u8 = match self.curve_type {
            CurveType::SECP256K1 => 0,
            CurveType::ED25519 => 1,
            CurveType::P256 => 2,
        };
        s.append(&tag);
        s.append_slice(&self.bytes);
    }
}

impl Deserializable for EcPubkey {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let tag: u8 = reader.read()?;
        let (curve_type, len) = match tag {
            0 => (CurveType::SECP256K1, 33),
            1 => (CurveType::ED25519, 32),
            2 => (CurveType::P256, 33),
            _ => return Err(serialization::Error::MalformedData)
        };
        let mut bytes = vec![0; len];
        reader.read_slice(&mut bytes)?;
        Ok(EcPubkey {
            curve_type,
            bytes
        })
    }
}

impl Serialize for EcPubkey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = serialize(self).take();
        s.serialize_str(&hex::encode(&bytes))
    }
}

impl<'de> Deserialize<'de> for EcPubkey {
    fn deserialize<D>(d: D) -> Result<EcPubkey, D::Error> where D: Deserializer<'de> {
        struct EcPubkeyVisitor;

        impl<'de> Visitor<'de> for EcPubkeyVisitor {
            type Value = EcPubkey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string containing EcPubkey data")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                let bytes = hex::decode(v).map_err(E::custom)?;
                deserialize(bytes.as_slice()).map_err(|e| E::custom(fomat!([e])))
            }
        }

        d.deserialize_any(EcPubkeyVisitor)
    }
}
