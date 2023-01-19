use crate::helpers_validation::SPVError;
use crate::work::{DifficultyAlgorithm, RETARGETING_INTERVAL};
use chain::{BlockHeader, BlockHeaderBits};
use primitives::hash::H256;
use serde::Deserialize;
use std::num::NonZeroU64;
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize)]
pub struct StartingBlockHeader {
    // Starting block height
    pub height: u64,
    // Hash of the starting block header.
    pub hash: Option<String>,
    // Time of the starting block header.
    pub time: u32,
    // Bits of the starting block header.
    pub bits: Option<u32>,
}

fn validate_btc_max_stored_headers_value(max_stored_block_headers: u64) -> Result<(), SPVError> {
    if RETARGETING_INTERVAL > max_stored_block_headers as u32 {
        return Err(SPVError::StartingBlockHeaderError(format!(
            "max_stored_block_headers {max_stored_block_headers} must be greater than retargeting interval {RETARGETING_INTERVAL}",
        )));
    }

    Ok(())
}

fn validate_btc_starting_header_height(coin: &str, height: u64) -> Result<(), SPVError> {
    let is_retarget = height % RETARGETING_INTERVAL as u64;
    if is_retarget != 0 {
        return Err(SPVError::WrongRetargetHeight {
            coin: coin.to_string(),
            expected_height: height - is_retarget,
        });
    }

    Ok(())
}

fn validate_btc_starting_header_bits_hash(coin: &str, header: &Option<StartingBlockHeader>) -> Result<(), SPVError> {
    if let Some(header) = header {
        if header.bits.is_none() {
            return Err(SPVError::BlockHeaderBitsError {
                coin: coin.to_string(),
                height: header.height,
            });
        }

        if header.hash.clone().unwrap_or_default().is_empty() {
            return Err(SPVError::BlockHeaderBitsError {
                coin: coin.to_string(),
                height: header.height,
            });
        }
    }

    Ok(())
}

/// SPV headers verification parameters
#[derive(Clone, Debug, Deserialize)]
pub struct BlockHeaderValidationParams {
    pub difficulty_check: bool,
    pub constant_difficulty: bool,
    pub difficulty_algorithm: Option<DifficultyAlgorithm>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SPVConf {
    /// Where to start block headers sync from.
    pub starting_block_header: Option<StartingBlockHeader>,
    /// Max number of block headers to be stored in db, when reached, old header will be deleted.
    pub max_stored_block_headers: Option<NonZeroU64>,
    /// The parameters that specify how the coin block headers should be validated. If None,
    /// headers will be saved in DB without validation, can be none if the coin's RPC server is trusted.
    pub validation_params: Option<BlockHeaderValidationParams>,
}

impl SPVConf {
    pub fn starting_block_header(&self) -> Result<StartingBlockHeader, SPVError> {
        if let Some(header) = &self.starting_block_header {
            return Ok(header.clone());
        };

        Err(SPVError::StartingBlockHeaderError(
            "Starting block header is missing from coin conf".to_string(),
        ))
    }

    pub fn starting_block_height(&self) -> u64 {
        self.starting_block_header
            .as_ref()
            .map(|e| e.height)
            .unwrap_or_default()
    }

    pub fn validate_spv_conf(&self, coin: &str) -> Result<(), SPVError> {
        if let Some(params) = &self.validation_params {
            if let Some(DifficultyAlgorithm::BitcoinMainnet) = &params.difficulty_algorithm {
                // Validate that starting block header is a retarget header.
                validate_btc_starting_header_height(coin, self.starting_block_height())?;
                // Validate that starting block header bits is not empty.
                validate_btc_starting_header_bits_hash(coin, &self.starting_block_header)?;
                // Validate that max_stored_headers_value is always greater than retarget interval.
                if let Some(max) = self.max_stored_block_headers {
                    validate_btc_max_stored_headers_value(max.into())?;
                }
            }
        }

        Ok(())
    }
}

/// `SPVVerificationHeader` is needed to use in place of `Blockheader` because of the limited data needed to perform
/// verifications.
#[derive(Clone)]
pub struct SPVVerificationHeader {
    // Starting block height
    pub height: u64,
    // Hash of the starting block header.
    pub hash: H256,
    // Time of the starting block header.
    pub time: u32,
    // Bits of the starting block header.
    pub bits: BlockHeaderBits,
}

impl From<BlockHeader> for SPVVerificationHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            height: 0,
            hash: value.hash(),
            time: value.time,
            bits: value.bits,
        }
    }
}

pub(crate) fn parse_verification_header(
    coin: &str,
    header: &StartingBlockHeader,
) -> Result<SPVVerificationHeader, SPVError> {
    let height = header.height;
    let hash = H256::from_str(
        header
            .hash
            .as_ref()
            .ok_or("")
            .map_err(|_| SPVError::BlockHeaderBitsError {
                coin: coin.to_string(),
                height,
            })?,
    )
    .map_err(|_| SPVError::BlockHeaderHashError {
        coin: coin.to_string(),
        height,
    })?;
    let Some(bits) = header.bits else { return Err(SPVError::BlockHeaderBitsError {
        coin: coin.to_string(),
        height,
    }) };

    Ok(SPVVerificationHeader {
        height,
        hash: hash.reversed(),
        time: header.time,
        bits: BlockHeaderBits::Compact(bits.into()),
    })
}
