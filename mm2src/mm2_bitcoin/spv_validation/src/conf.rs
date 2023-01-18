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

fn validate_btc_starting_header_bits(coin: &str, header: &Option<StartingBlockHeader>) -> Result<(), SPVError> {
    if let Some(header) = header {
        if header.height > 0 && header.bits.is_none() {
            return Err(SPVError::InvalidBits(coin.to_string()));
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
    pub fn starting_block_header(&self) -> Result<SPVVerificationHeader, SPVError> {
        if let Some(header) = &self.starting_block_header {
            return Ok(header.clone().into());
        };

        Err(SPVError::StartingBlockHeaderError(
            "Starting block header is missing from coin conf".to_string(),
        ))
    }

    pub fn starting_block_height(&self) -> u64 {
        if let Some(header) = &self.starting_block_header {
            return header.height;
        };

        0
    }

    pub fn validate_spv_conf(&self, coin: &str) -> Result<(), SPVError> {
        if let Some(params) = &self.validation_params {
            if let Some(DifficultyAlgorithm::BitcoinMainnet) = &params.difficulty_algorithm {
                // Validate that starting block header is a retarget header.
                validate_btc_starting_header_height(coin, self.starting_block_height())?;
                // Validate that starting block header bits is not empty.
                validate_btc_starting_header_bits(coin, &self.starting_block_header)?;
                // Validate that max_stored_headers_value is always greater than retarget interval.
                if let Some(max) = self.max_stored_block_headers {
                    validate_btc_max_stored_headers_value(max.into())?;
                }
            }
        }

        Ok(())
    }
}

/// `SPVVerificationHeader` is needed to use in place of `Blockheader` because of the limited data needed to perform validations.
#[derive(Clone)]
pub struct SPVVerificationHeader {
    // Starting block height
    pub height: u64,
    // Hash of the starting block header.
    pub hash: Option<H256>,
    // Time of the starting block header.
    pub time: u32,
    // Bits of the starting block header.
    pub bits: Option<BlockHeaderBits>,
}

impl From<StartingBlockHeader> for SPVVerificationHeader {
    fn from(value: StartingBlockHeader) -> Self {
        Self {
            height: value.height,
            hash: value.hash.map(|hash| H256::from_str(&hash).unwrap_or_default()),
            time: value.time,
            bits: value.bits.map(|bits| BlockHeaderBits::Compact(bits.into())),
        }
    }
}

impl SPVVerificationHeader {
    pub(crate) fn hash(&self, coin: &str) -> Result<H256, SPVError> {
        let Some(hash) = self.hash else {
            return Err(SPVError::UnexpectedStartingBlockHeaderHash(coin.to_string()));
        };

        Ok(hash)
    }

    pub(crate) fn bits(&self, coin: &str) -> Result<BlockHeaderBits, SPVError> {
        let Some(bits) = &self.bits else {
            return Err(SPVError::InvalidBits(coin.to_string()))
        };

        Ok(BlockHeaderBits::Compact(bits.clone().into()))
    }
}

impl From<BlockHeader> for SPVVerificationHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            height: 0,
            hash: Some(value.hash()),
            time: value.time,
            bits: Some(value.bits),
        }
    }
}
