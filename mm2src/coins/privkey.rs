
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  LP_utxos.c
//  marketmaker
//

use bitcrypto::{ChecksumType, sha256};
use common::crypto::{CurveType, EcPrivkey};
use crate::tezos::TezosSecret;
use crate::tezos::tezos_constants::*;
use keys::{Error as KeysError, KeyPair, Private as UtxoWif};
use primitives::hash::H256;

pub fn ec_privkey_from_seed(seed: &str) -> Result<EcPrivkey, String> {
    match seed.parse::<UtxoWif>() {
        Ok(private) => {
            if !private.compressed {return ERR!("We only support compressed keys at the moment")}
            return Ok(try_s!(EcPrivkey::new(CurveType::SECP256K1, &*private.secret)))
        },
        Err(e) => match e {
            KeysError::InvalidChecksum => return ERR!("Provided WIF passphrase has invalid checksum!"),
            _ => (), // ignore other errors, assume the passphrase is not WIF
        },
    };

    if seed.starts_with("edsk") || seed.starts_with("spsk") || seed.starts_with("p2sk") {
        let tezos_secret: TezosSecret = try_s!(seed.parse());
        let curve_type = match tezos_secret.prefix {
            ED_SK_PREFIX => CurveType::ED25519,
            SECP_SK_PREFIX => CurveType::SECP256K1,
            P256_SK_PREFIX => CurveType::P256,
            _ => return ERR!("Unsupported prefix {:?}", tezos_secret.prefix),
        };
        let ec_privkey = try_s!(EcPrivkey::new(curve_type, &tezos_secret.data));
        return Ok(ec_privkey);
    }

    if seed.starts_with("0x") {
        let hash: H256 = try_s!((&seed[2..]).parse());
        let priv_key = try_s!(EcPrivkey::new(CurveType::SECP256K1, &*hash));
        Ok(priv_key)
    } else {
        let mut hash = sha256(seed.as_bytes());
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;
        let priv_key = try_s!(EcPrivkey::new(CurveType::SECP256K1, &*hash));
        Ok(priv_key)
    }
}
