use base58::{FromBase58Error};
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum FromStrErr {
    InvalidBase58(FromBase58Error),
    InvalidLength,
    InvalidCheckSum,
}

impl fmt::Display for FromStrErr {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        format!("{:?}", self).fmt(f)
    }
}

#[macro_export]
macro_rules! impl_base58_checksum_encoding {
    ($impl_for:ident, $visitor:ident $(, ($prefix_len:expr, $total_len:expr))*) => {
        impl FromStr for $impl_for {
            type Err = common::base58_checksum_encoding::FromStrErr;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let bytes = s.from_base58().map_err(|e| common::base58_checksum_encoding::FromStrErr::InvalidBase58(e))?;
                let len = bytes.len();
                let prefix_len = match len {
                    $(
                        $total_len => $prefix_len,
                    )*
                    _ => return Err(common::base58_checksum_encoding::FromStrErr::InvalidLength),
                };
                let checksum = dhash256(&bytes[..len - 4]);
                if bytes[len - 4..] != checksum[..4] {
                    return Err(common::base58_checksum_encoding::FromStrErr::InvalidCheckSum);
                }
                Ok($impl_for {
                    prefix: unwrap!(bytes[..prefix_len].try_into(), "slice with incorrect length"),
                    data: (&bytes[prefix_len..len - 4]).into(),
                })
            }
        }

        impl fmt::Display for $impl_for {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut bytes = vec![];
                bytes.extend_from_slice(&self.prefix);
                bytes.extend_from_slice(&*self.data);
                let checksum = dhash256(&bytes);
                bytes.extend_from_slice(&checksum[..4]);
                bytes.to_base58().fmt(f)
            }
        }

        impl serde::Serialize for $impl_for {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
                s.serialize_str(&self.to_string())
            }
        }

        impl<'de> serde::de::Deserialize<'de> for $impl_for {
            fn deserialize<D>(d: D) -> Result<$impl_for, D::Error> where D: serde::de::Deserializer<'de> {
                struct $visitor;

                impl<'de> Visitor<'de> for $visitor {
                    type Value = $impl_for;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str("a string containing base58 checksum encoded data")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                    {
                        v.parse().map_err(|e| E::custom(fomat!([e])))
                    }
                }

                d.deserialize_any($visitor)
            }
        }
    }
}
