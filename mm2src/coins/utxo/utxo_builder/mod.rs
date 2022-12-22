mod utxo_arc_builder;
mod utxo_coin_builder;
mod utxo_conf_builder;

pub use utxo_arc_builder::{BlockHeaderUtxoArcOps, MergeUtxoArcOps, UtxoArcBuilder};
pub use utxo_coin_builder::{UtxoCoinBuildError, UtxoCoinBuildResult, UtxoCoinBuilder, UtxoCoinBuilderCommonOps,
                            UtxoFieldsWithGlobalHDBuilder, UtxoFieldsWithHardwareWalletBuilder,
                            UtxoFieldsWithIguanaSecretBuilder};
pub use utxo_conf_builder::{UtxoConfBuilder, UtxoConfError, UtxoConfResult};

#[cfg(test)]
pub(crate) use utxo_arc_builder::{block_header_utxo_loop, calc_block_headers_limit_to_remove,
                                  BlockHeaderUtxoLoopExtraArgs};
