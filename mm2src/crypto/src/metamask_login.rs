use lazy_static::lazy_static;
use mm2_metamask::{Eip712, ObjectType, PropertyType};

pub const ADEX_LOGIN_TYPE: &str = "AtomicDEXLogin";

lazy_static! {
    static ref ADEX_TYPES: [ObjectType; 2] = adex_login_types();
}

pub fn adex_eip712_request(
    domain: AtomicDEXDomain,
    req: AtomicDEXLoginRequest,
) -> Eip712<AtomicDEXDomain, AtomicDEXLoginRequest> {
    let types = ADEX_TYPES
        .iter()
        .map(|object_type| (object_type.name.clone(), object_type.properties.clone()))
        .collect();
    Eip712 {
        types,
        domain,
        primary_type: ADEX_LOGIN_TYPE.to_string(),
        message: req,
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AtomicDEXDomain {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) version: String,
}

#[derive(Debug, Serialize)]
pub struct AtomicDEXLoginRequest {
    message: String,
}

impl AtomicDEXLoginRequest {
    pub fn with_domain_name(domain_name: String) -> AtomicDEXLoginRequest {
        AtomicDEXLoginRequest {
            message: format!("Login to {domain_name}"),
        }
    }
}

fn adex_login_types() -> [ObjectType; 2] {
    let mut domain = ObjectType::domain();
    domain.property("name", PropertyType::String);
    domain.property("url", PropertyType::String);
    domain.property("version", PropertyType::String);

    let mut login_request = ObjectType::new(ADEX_LOGIN_TYPE);
    login_request.property("message", PropertyType::String);

    [domain, login_request]
}

mod tests {
    use super::*;
    use mm2_metamask::hash_typed_data;
    use std::str::FromStr;
    use wasm_bindgen_test::*;
    use web3::types::H256;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    async fn test_hash_adex_login_request() {
        let domain = AtomicDEXDomain {
            name: "AtomicDEX".to_string(),
            url: "https://atomicdex.io".to_string(),
            version: "1.0".to_string(),
        };
        let request = AtomicDEXLoginRequest::with_domain_name(domain.name.clone());
        let adex_req = adex_eip712_request(domain, request);

        let actual = hash_typed_data(adex_req).unwrap();
        let expected = H256::from_str("efa58ae0c74c622d4ba3ef661b1b0fec42ac0fe7bd28354d30fe32b097f34c8c").unwrap();
        assert_eq!(actual, expected);
    }
}
