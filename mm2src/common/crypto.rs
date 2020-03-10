use bitcrypto::{dhash160, keccak256, sha256};
use blake2::{VarBlake2b};
use blake2::digest::{Input, VariableOutput};
use ed25519_dalek::{Keypair as EdKeypair, PublicKey as EdPublicKey, SecretKey as EdSecret,
                    Signature as EdSignature};
use primitives::hash::{H160, H256, H512};
use secp256k1::{Message as SecpMessage, PublicKey as SecpPublicKey, SecretKey as SecpSecret,
                sign as secp_sign, Signature as SecpSignature, verify as secp_verify_sig};
use serialization::{Deserializable, deserialize, Reader, Serializable, serialize, Stream};
use serde::{Serialize, Serializer, Deserialize};
use serde::de::{Deserializer, Visitor};
use sha2::{Digest, Sha512};

pub fn blake2b_160(input: &[u8]) -> H160 {
    let mut blake = unwrap!(VarBlake2b::new(20));
    blake.input(&input);
    H160::from(blake.vec_result().as_slice())
}

pub fn blake2b_256(input: &[u8]) -> H256 {
    let mut blake = unwrap!(VarBlake2b::new(32));
    blake.input(&input);
    H256::from(blake.vec_result().as_slice())
}

pub fn sha512(input: &[u8]) -> H512 {
    let mut sha = Sha512::default();
    sha2::Digest::input(&mut sha, input);
    H512::from(sha.result().as_slice())
}

pub trait CryptoOps {
    fn get_pubkey(&self) -> EcPubkey;

    fn sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurveType {
    ED25519,
    SECP256K1,
    P256,
}

#[derive(Debug)]
pub enum EcPrivkey {
    ED25519(EdSecret),
    SECP256K1(SecpSecret),
}

impl PartialEq for EcPrivkey {
    fn eq(&self, other: &EcPrivkey) -> bool {
        match self {
            EcPrivkey::ED25519(lhs) => {
                match other {
                    EcPrivkey::ED25519(rhs) => lhs.as_bytes() == rhs.as_bytes(),
                    EcPrivkey::SECP256K1(_) => false,
                }
            },
            EcPrivkey::SECP256K1(lhs) => {
                match other {
                    EcPrivkey::ED25519(_) => false,
                    EcPrivkey::SECP256K1(rhs) => lhs == rhs,
                }
            }
        }
    }
}

impl EcPrivkey {
    pub fn new(curve_type: CurveType, bytes: &[u8]) -> Result<EcPrivkey, String> {
        match curve_type {
            CurveType::ED25519 => {
                let secret = try_s!(EdSecret::from_bytes(bytes));
                Ok(EcPrivkey::ED25519(secret))
            },
            CurveType::SECP256K1 => {
                let secret = try_s!(SecpSecret::parse_slice(bytes).map_err(|e| ERRL!("{:?}", e)));
                Ok(EcPrivkey::SECP256K1(secret))
            },
            CurveType::P256 => ERR!("CurveType::P256 is not supported currently")
        }
    }

    pub fn get_bytes(&self) -> [u8; 32] {
        match self {
            EcPrivkey::ED25519(s) => s.to_bytes(),
            EcPrivkey::SECP256K1(s) => s.serialize(),
        }
    }

    pub fn get_pubkey(&self) -> EcPubkey {
        match self {
            EcPrivkey::ED25519(s) => {
                let public = EdPublicKey::from_secret::<Sha512>(s);
                EcPubkey {
                    curve_type: CurveType::ED25519,
                    bytes: public.as_bytes().to_vec()
                }
            },
            EcPrivkey::SECP256K1(s) => {
                let public = SecpPublicKey::from_secret_key(s);
                EcPubkey {
                    curve_type: CurveType::SECP256K1,
                    bytes: public.serialize_compressed().to_vec(),
                }
            },
        }
    }

    pub fn sign_message(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            EcPrivkey::ED25519(s) => {
                let public = EdPublicKey::from_secret::<Sha512>(s);
                let mut bytes = vec![];
                bytes.extend_from_slice(s.as_bytes());
                bytes.extend_from_slice(public.as_bytes());
                let key_pair = try_s!(EdKeypair::from_bytes(&bytes));
                Ok(key_pair.sign::<Sha512>(&msg).to_bytes().to_vec())
            },
            EcPrivkey::SECP256K1(s) => {
                let msg = try_s!(SecpMessage::parse_slice(&msg).map_err(|e| ERRL!("{:?}", e)));
                secp_sign(&msg, s).map(|(sig, _)| sig.serialize_der().as_ref().to_vec()).map_err(|e| ERRL!("{:?}", e))
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcPubkey {
    pub curve_type: CurveType,
    pub bytes: Vec<u8>,
}

impl EcPubkey {
    pub fn verify_signature(&self, msg: &[u8], sig: &[u8]) -> Result<(), String> {
        match self.curve_type {
            CurveType::ED25519 => {
                let public = try_s!(EdPublicKey::from_bytes(&self.bytes));
                let sig = try_s!(EdSignature::from_bytes(sig));
                public.verify::<Sha512>(msg, &sig).map_err(|e| ERRL!("{}", e))
            },
            CurveType::SECP256K1 => {
                let public = try_s!(SecpPublicKey::parse_slice(&self.bytes, None).map_err(|e| ERRL!("{:?}", e)));
                let sig = try_s!(SecpSignature::parse_der(sig).map_err(|e| ERRL!("{:?}", e)));
                let msg = try_s!(SecpMessage::parse_slice(msg).map_err(|e| ERRL!("{:?}", e)));
                if secp_verify_sig(&msg, &sig, &public) {
                    Ok(())
                } else {
                    ERR!("Invalid signature")
                }
            },
            CurveType::P256 => ERR!("CurveType::P256 is not supported currently"),
        }
    }
}

impl Default for EcPubkey {
    fn default() -> EcPubkey {
        EcPubkey {
            curve_type: CurveType::SECP256K1,
            bytes: vec![0; 33],
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

impl Serializable for EcPrivkey {
    fn serialize(&self, s: &mut Stream) {
        match self {
            EcPrivkey::SECP256K1(secret) => {
                s.append(&0u8);
                s.append_slice(&secret.serialize())
            },
            EcPrivkey::ED25519(secret) => {
                s.append(&1u8);
                s.append_slice(secret.as_bytes())
            },
        };
    }
}

impl Deserializable for EcPrivkey {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let tag: u8 = reader.read()?;
        let curve_type = match tag {
            0 => CurveType::SECP256K1,
            1 => CurveType::ED25519,
            _ => return Err(serialization::Error::Custom(ERRL!("Unknown tag {}", tag)))
        };
        let mut bytes = [0; 32];
        reader.read_slice(&mut bytes)?;
        let privkey = EcPrivkey::new(curve_type, &bytes).map_err(|e| serialization::Error::Custom(ERRL!("!EcPrivkey::new {}", e)))?;
        Ok(privkey)
    }
}

impl Serialize for EcPrivkey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = serialize(self).take();
        s.serialize_str(&hex::encode(&bytes))
    }
}

impl<'de> Deserialize<'de> for EcPrivkey {
    fn deserialize<D>(d: D) -> Result<EcPrivkey, D::Error> where D: Deserializer<'de> {
        struct EcPrivkeyVisitor;

        impl<'de> Visitor<'de> for EcPrivkeyVisitor {
            type Value = EcPrivkey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string containing EcPrivkey data")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                let bytes = hex::decode(v).map_err(E::custom)?;
                deserialize(bytes.as_slice()).map_err(|e| E::custom(fomat!([e])))
            }
        }

        d.deserialize_any(EcPrivkeyVisitor)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretHashAlgo {
    Ripe160Sha256,
    Sha256,
    Sha512,
    Blake2b256,
    Keccak256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretHash {
    Ripe160Sha256(H160),
    Sha256(H256),
    Sha512(H512),
    Blake2b(H256),
    Keccak256(H256),
}

impl Default for SecretHash {
    fn default() -> Self {
        SecretHash::Ripe160Sha256(H160::default())
    }
}

impl SecretHash {
    pub fn from_secret(hash_type: SecretHashAlgo, secret: &[u8]) -> SecretHash {
        match hash_type {
            SecretHashAlgo::Ripe160Sha256 => SecretHash::Ripe160Sha256(dhash160(secret)),
            SecretHashAlgo::Sha256 => SecretHash::Sha256(sha256(secret)),
            SecretHashAlgo::Sha512 => SecretHash::Sha512(sha512(secret)),
            SecretHashAlgo::Blake2b256 => SecretHash::Blake2b(blake2b_256(secret)),
            SecretHashAlgo::Keccak256 => SecretHash::Blake2b(keccak256(secret)),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            SecretHash::Ripe160Sha256(hash) => hash.to_vec(),
            SecretHash::Sha256(hash) => hash.to_vec(),
            SecretHash::Sha512(hash) => hash.to_vec(),
            SecretHash::Blake2b(hash) => hash.to_vec(),
            SecretHash::Keccak256(hash) => hash.to_vec(),
        }
    }

    pub fn get_algo(&self) -> SecretHashAlgo {
        match self {
            SecretHash::Ripe160Sha256(_) => SecretHashAlgo::Ripe160Sha256,
            SecretHash::Sha256(_) => SecretHashAlgo::Sha256,
            SecretHash::Sha512(_) => SecretHashAlgo::Sha512,
            SecretHash::Blake2b(_) => SecretHashAlgo::Blake2b256,
            SecretHash::Keccak256(_) => SecretHashAlgo::Keccak256,
        }
    }
}

impl Serializable for SecretHash {
    fn serialize(&self, s: &mut Stream) {
        match self {
            SecretHash::Ripe160Sha256(hash) => {
                s.append(&0u8);
                s.append(hash);
            },
            SecretHash::Sha256(hash) => {
                s.append(&1u8);
                s.append(hash);
            },
            SecretHash::Sha512(hash) => {
                s.append(&2u8);
                s.append(hash);
            },
            SecretHash::Blake2b(hash) => {
                s.append(&3u8);
                s.append(hash);
            },
            SecretHash::Keccak256(hash) => {
                s.append(&4u8);
                s.append(hash);
            },
        };
    }
}

impl Deserializable for SecretHash {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let tag: u8 = reader.read()?;
        match tag {
            0 => Ok(SecretHash::Ripe160Sha256(reader.read()?)),
            1 => Ok(SecretHash::Sha256(reader.read()?)),
            2 => Ok(SecretHash::Blake2b(reader.read()?)),
            _ => Err(serialization::Error::MalformedData)
        }
    }
}

impl Serialize for SecretHash {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = serialize(self).take();
        s.serialize_str(&hex::encode(&bytes))
    }
}

impl<'de> Deserialize<'de> for SecretHash {
    fn deserialize<D>(d: D) -> Result<SecretHash, D::Error> where D: Deserializer<'de> {
        struct SecretHashVisitor;

        impl<'de> Visitor<'de> for SecretHashVisitor {
            type Value = SecretHash;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string containing SecretHash data")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                let bytes = hex::decode(v).map_err(E::custom)?;
                deserialize(bytes.as_slice()).map_err(|e| E::custom(fomat!([e])))
            }
        }

        d.deserialize_any(SecretHashVisitor)
    }
}

impl From<[u8; 20]> for SecretHash {
    fn from(input: [u8; 20]) -> SecretHash {
        SecretHash::Ripe160Sha256(input.into())
    }
}
