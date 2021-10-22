use std::fmt;
use std::str::FromStr;

pub const HARDENED_PATH: u32 = 2147483648;

/// The implementation is inspired by
/// https://github.com/tezedge/tezedge-client/blob/master/types/src/key_derivation_path.rs
#[derive(PartialEq, Debug, Clone)]
pub struct KeyDerivationPath(Vec<u32>);

impl fmt::Display for KeyDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path_str = self
            .0
            .iter()
            .map(|num| {
                if *num >= HARDENED_PATH {
                    format!("{}'", num - HARDENED_PATH)
                } else {
                    format!("{}", num)
                }
            })
            .collect::<Vec<_>>()
            .join("/");

        write!(f, "m/{}", path_str)
    }
}

impl KeyDerivationPath {
    pub fn take(self) -> Vec<u32> { self.0 }
}

impl AsRef<[u32]> for KeyDerivationPath {
    fn as_ref(&self) -> &[u32] { &self.0 }
}

impl FromStr for KeyDerivationPath {
    type Err = String;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if !path.starts_with("m/") {
            return Err(format!("Bad prefix. Path: {}", path));
        }

        Ok(KeyDerivationPath(
            path.replace("m/", "")
                .split('/')
                .enumerate()
                .map(|(_index, part)| {
                    let mut num_str = part.to_string();
                    let is_hardened = num_str.ends_with('\'');

                    if is_hardened {
                        // remove the tick(')
                        num_str.pop();
                    }

                    num_str
                        .parse::<u32>()
                        .map(|num| if is_hardened { num + HARDENED_PATH } else { num })
                        .map_err(|_| format!("Bad number. Path: {}", path.to_string()))
                })
                .collect::<Result<_, _>>()?,
        ))
    }
}
