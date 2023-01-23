use crate::helpers_validation::SPVError;
use crate::work::{DifficultyAlgorithm, RETARGETING_INTERVAL};
use chain::{BlockHeader, BlockHeaderBits};
use primitives::hash::H256;
use serde::Deserialize;
use std::num::NonZeroU64;
use std::str::FromStr;

/// Custom SPV starting block header configuration
#[derive(Debug, Clone, Deserialize)]
pub struct StartingBlockHeader {
    /// Valid `u32` representation of the block `heigh`t.
    pub height: u64,
    /// Valid `String` representation of the block header `hash`.
    pub hash: String,
    /// Valid `u32` representation of the `date` the block is mined in epoch.
    pub time: u32,
    /// Valid `u32` representation of `bits` for the block header.
    pub bits: u32,
}

/// Validate that `max_stored_headers_value` is always greater than `retarget interval`.
fn validate_btc_max_stored_headers_value(max_stored_block_headers: u64) -> Result<(), SPVError> {
    if RETARGETING_INTERVAL > max_stored_block_headers as u32 {
        return Err(SPVError::StartingBlockHeaderError(format!(
            "max_stored_block_headers {max_stored_block_headers} must be greater than retargeting interval {RETARGETING_INTERVAL}",
        )));
    }

    Ok(())
}

/// Validate that starting block header is a retarget header.
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

/// Validate that starting_header_hash is a valid `H256`.
fn validate_starting_header_hash(coin: &str, header: &StartingBlockHeader) -> Result<(), SPVError> {
    H256::from_str(&header.hash).map_err(|_| SPVError::BlockHeaderHashError {
        coin: coin.to_string(),
        height: header.height,
    })?;

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
    pub starting_block_header: StartingBlockHeader,
    /// Max number of block headers to be stored in db, when reached, old header will be deleted.
    pub max_stored_block_headers: Option<NonZeroU64>,
    /// The parameters that specify how the coin block headers should be validated. If None,
    /// headers will be saved in DB without validation, can be none if the coin's RPC server is trusted.
    pub validation_params: Option<BlockHeaderValidationParams>,
}

impl SPVConf {
    pub fn validate(&self, coin: &str) -> Result<(), SPVError> {
        validate_starting_header_hash(coin, &self.starting_block_header)?;

        if let Some(params) = &self.validation_params {
            if let Some(DifficultyAlgorithm::BitcoinMainnet) = &params.difficulty_algorithm {
                validate_btc_starting_header_height(coin, self.starting_block_header.height)?;
                if let Some(max) = self.max_stored_block_headers {
                    validate_btc_max_stored_headers_value(max.into())?;
                }
            }
        }

        Ok(())
    }

    pub(crate) fn get_verification_header(&self, coin: &str) -> Result<SPVVerificationHeader, SPVError> {
        let header = &self.starting_block_header;
        let height = header.height;
        let hash = H256::from_str(&header.hash).map_err(|_| SPVError::BlockHeaderHashError {
            coin: coin.to_string(),
            height,
        })?;

        Ok(SPVVerificationHeader {
            hash: hash.reversed(),
            time: header.time,
            bits: BlockHeaderBits::Compact(header.bits.into()),
        })
    }
}

/// `SPVVerificationHeader` is needed to use in place of `Blockheader` because of the limited data needed to perform
/// verifications.
#[derive(Clone)]
pub struct SPVVerificationHeader {
    /// Hash of the starting block header.
    pub hash: H256,
    /// Time of the starting block header.
    pub time: u32,
    /// Bits of the starting block header.
    pub bits: BlockHeaderBits,
}

impl From<BlockHeader> for SPVVerificationHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            hash: value.hash(),
            time: value.time,
            bits: value.bits,
        }
    }
}
