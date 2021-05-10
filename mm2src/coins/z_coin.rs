use crate::utxo::utxo_common::{big_decimal_from_sat_unsigned, p2sh_spend, payment_script};
use crate::utxo::{utxo_common::UtxoArcBuilder, UtxoArc, UtxoCoinBuilder};
use crate::z_coin::z_rpc::{ZSendManyHtlcParams, ZSendManyItem};
use crate::{BalanceFut, CoinBalance, FoundSwapTxSpend, MarketCoinOps, SwapOps, TransactionEnum, TransactionFut};
use bitcrypto::dhash160;
use chain::Transaction as UtxoTx;
use common::executor::Timer;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::mm_number::{BigDecimal, MmNumber};
use common::privkey::key_pair_from_seed;
use futures::compat::Future01CompatExt;
use futures::{FutureExt, TryFutureExt, TryStreamExt};
use futures01::Future;
use keys::{Address, Public};
use rpc::v1::types::Bytes;
use script::{Builder as ScriptBuilder, Opcode};
use serde_json::{self as json, Value as Json};
use serialization::{deserialize, serialize};
use zcash_client_backend::encoding::{encode_extended_spending_key, encode_payment_address};
use zcash_primitives::{constants::mainnet as z_mainnet_constants, primitives::PaymentAddress,
                       zip32::ExtendedSpendingKey};

mod z_rpc;
use common::now_ms;
use script::TransactionInputSigner;
use z_rpc::ZOperationStatus;

#[cfg(test)] mod z_coin_tests;

#[derive(Clone, Debug)]
pub struct ZCoin {
    utxo_arc: UtxoArc,
    z_spending_key: ExtendedSpendingKey,
    z_addr: PaymentAddress,
}

#[derive(Debug)]
pub enum ZCoinBuildError {
    BuilderError(String),
    GetAddressError,
}

pub async fn z_coin_from_conf_and_request(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    req: &Json,
    secp_priv_key: &[u8],
    z_spending_key: ExtendedSpendingKey,
) -> Result<ZCoin, MmError<ZCoinBuildError>> {
    let builder = UtxoArcBuilder::new(ctx, ticker, conf, req, secp_priv_key);
    let utxo_arc = builder
        .build()
        .await
        .map_err(|e| MmError::new(ZCoinBuildError::BuilderError(e)))?;

    let (_, z_addr) = z_spending_key
        .default_address()
        .map_err(|_| MmError::new(ZCoinBuildError::GetAddressError))?;
    Ok(ZCoin {
        utxo_arc,
        z_spending_key,
        z_addr,
    })
}

impl MarketCoinOps for ZCoin {
    fn ticker(&self) -> &str { todo!() }

    fn my_address(&self) -> Result<String, String> { todo!() }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let my_address = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &self.z_addr);
        let min_conf = 0;
        let fut = self
            .utxo_arc
            .rpc_client
            .as_ref()
            .z_get_balance(&my_address, min_conf)
            // at the moment Z coins do not have an unspendable balance
            .map(|spendable| CoinBalance {
                spendable: spendable.to_decimal(),
                unspendable: BigDecimal::from(0),
            })
            .map_err(|e| e.into());
        Box::new(fut)
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { todo!() }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> { todo!() }

    fn wait_for_confirmations(
        &self,
        tx: &[u8],
        confirmations: u64,
        requires_nota: bool,
        wait_until: u64,
        check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn wait_for_tx_spend(
        &self,
        transaction: &[u8],
        wait_until: u64,
        from_block: u64,
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        todo!()
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> { todo!() }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> { todo!() }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> { todo!() }

    fn display_priv_key(&self) -> String { todo!() }

    fn min_tx_amount(&self) -> BigDecimal { todo!() }

    fn min_trading_vol(&self) -> MmNumber { todo!() }
}

impl SwapOps for ZCoin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: BigDecimal) -> TransactionFut { todo!() }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        let taker_pub = try_fus!(Public::from_slice(taker_pub));
        let payment_script = payment_script(time_lock, secret_hash, self.utxo_arc.key_pair.public(), &taker_pub);
        let hash = dhash160(&payment_script);
        let htlc_address = Address {
            prefix: self.utxo_arc.conf.p2sh_addr_prefix,
            t_addr_prefix: self.utxo_arc.conf.p2sh_t_addr_prefix,
            hash,
            checksum_type: self.utxo_arc.conf.checksum_type,
        };
        let selfi = self.clone();
        let fut = async move {
            let from_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &selfi.z_addr);
            let send_item = ZSendManyItem {
                amount,
                op_return: Some(payment_script.to_vec().into()),
                address: htlc_address.to_string(),
            };

            let op_id = try_s!(
                selfi
                    .utxo_arc
                    .rpc_client
                    .as_ref()
                    .z_send_many(&from_addr, vec![send_item])
                    .compat()
                    .await
            );

            loop {
                let operation_statuses = try_s!(
                    selfi
                        .utxo_arc
                        .rpc_client
                        .as_ref()
                        .z_get_send_many_status(&[&op_id])
                        .compat()
                        .await
                );

                match operation_statuses.first() {
                    Some(ZOperationStatus::Executing { .. }) => {
                        Timer::sleep(1.).await;
                        continue;
                    },
                    Some(ZOperationStatus::Failed { .. }) => {
                        break ERR!("Operation {:?} failed", operation_statuses);
                    },
                    Some(ZOperationStatus::Success { result, .. }) => {
                        let tx_bytes = try_s!(
                            selfi
                                .utxo_arc
                                .rpc_client
                                .get_transaction_bytes(result.txid.clone())
                                .compat()
                                .await
                        );
                        let tx: UtxoTx = try_s!(deserialize(tx_bytes.0.as_slice()).map_err(|e| format!("{:?}", e)));
                        break Ok(tx.into());
                    },
                    None => break ERR!("operation_statuses are empty"),
                }
            }
        };
        Box::new(fut.boxed().compat())
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        todo!()
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        todo!()
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        todo!()
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        todo!()
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        swap_contract_address: &Option<Bytes>,
    ) -> TransactionFut {
        let tx: UtxoTx = deserialize(maker_payment_tx).unwrap();
        let amount = big_decimal_from_sat_unsigned(tx.outputs[0].value - 10000, self.utxo_arc.decimals);
        let send_to = ZSendManyItem {
            amount,
            op_return: None,
            address: encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &self.z_addr),
        };

        println!("{}", json::to_string(&send_to).unwrap());
        let slice: &[u8] = &*self.utxo_arc.key_pair.public();
        let htlc_params = ZSendManyHtlcParams {
            pubkey: taker_pub.into(),
            refund_pubkey: slice.into(),
            secret_hash: secret_hash.into(),
            input_txid: tx.hash().reversed().into(),
            input_index: 0,
            input_amount: tx.outputs[0].value.into(),
            locktime: time_lock,
        };
        println!("{}", json::to_string(&htlc_params).unwrap());

        let redeem_script = payment_script(
            time_lock,
            secret_hash,
            self.utxo_arc.key_pair.public(),
            &Public::from_slice(taker_pub).unwrap(),
        )
        .to_vec();
        let from_addr = Address {
            prefix: self.utxo_arc.conf.p2sh_addr_prefix,
            t_addr_prefix: self.utxo_arc.conf.p2sh_t_addr_prefix,
            hash: dhash160(&redeem_script),
            checksum_type: self.utxo_arc.conf.checksum_type,
        }
        .to_string();
        println!("{}", from_addr);
        let selfi = self.clone();
        let fut = async move {
            let op_id = try_s!(
                selfi
                    .utxo_arc
                    .rpc_client
                    .as_ref()
                    .z_send_many_template(&from_addr, vec![send_to], htlc_params)
                    .compat()
                    .await
            );

            loop {
                let operation_statuses = try_s!(
                    selfi
                        .utxo_arc
                        .rpc_client
                        .as_ref()
                        .z_get_send_many_template_status(&[&op_id])
                        .compat()
                        .await
                );

                match operation_statuses.first() {
                    Some(ZOperationStatus::Executing { .. }) => {
                        Timer::sleep(1.).await;
                        continue;
                    },
                    Some(ZOperationStatus::Failed { .. }) => {
                        break ERR!("Operation {:?} failed", operation_statuses);
                    },
                    Some(ZOperationStatus::Success { result, .. }) => {
                        let mut refund_tx: UtxoTx =
                            try_s!(deserialize(result.hex.0.as_slice()).map_err(|e| format!("{:?}", e)));
                        let mut signer: TransactionInputSigner = refund_tx.clone().into();
                        signer.consensus_branch_id = selfi.utxo_arc.conf.consensus_branch_id;
                        signer.inputs[0].amount = tx.outputs[0].value;
                        let script_data = ScriptBuilder::default().push_opcode(Opcode::OP_1).into_script();
                        let signed_input = p2sh_spend(
                            &signer,
                            0,
                            &selfi.utxo_arc.key_pair,
                            script_data,
                            redeem_script.clone().into(),
                            selfi.utxo_arc.conf.signature_version,
                            selfi.utxo_arc.conf.fork_id,
                        )
                        .unwrap();
                        refund_tx.inputs[0] = signed_input;
                        let tx_bytes = serialize(&refund_tx);
                        try_s!(
                            selfi
                                .utxo_arc
                                .rpc_client
                                .send_raw_transaction(tx_bytes.into())
                                .compat()
                                .await
                        );
                        break Ok(refund_tx.into());
                    },
                    None => break ERR!("operation_statuses are empty"),
                }
            }
        };
        Box::new(fut.boxed().compat())
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        expected_sender: &[u8],
        fee_addr: &[u8],
        amount: &BigDecimal,
        min_block_number: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn validate_maker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
        swap_contract_address: &Option<Bytes>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn validate_taker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
        swap_contract_address: &Option<Bytes>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        todo!()
    }

    fn check_if_my_payment_sent(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        search_from_block: u64,
        swap_contract_address: &Option<Bytes>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        todo!()
    }

    fn search_for_swap_tx_spend_my(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
        swap_contract_address: &Option<Bytes>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        todo!()
    }

    fn search_for_swap_tx_spend_other(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
        swap_contract_address: &Option<Bytes>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        todo!()
    }

    fn extract_secret(&self, secret_hash: &[u8], spend_tx: &[u8]) -> Result<Vec<u8>, String> { todo!() }
}

#[test]
fn derive_z_key_from_mm_seed() {
    let seed = "spice describe gravity federal blast come thank unfair canal monkey style afraid";
    let secp_keypair = key_pair_from_seed(seed).unwrap();
    let z_spending_key = ExtendedSpendingKey::master(&*secp_keypair.private().secret);
    let encoded = encode_extended_spending_key(z_mainnet_constants::HRP_SAPLING_EXTENDED_SPENDING_KEY, &z_spending_key);
    assert_eq!(encoded, "secret-extended-key-main1qqqqqqqqqqqqqqytwz2zjt587n63kyz6jawmflttqu5rxavvqx3lzfs0tdr0w7g5tgntxzf5erd3jtvva5s52qx0ms598r89vrmv30r69zehxy2r3vesghtqd6dfwdtnauzuj8u8eeqfx7qpglzu6z54uzque6nzzgnejkgq569ax4lmk0v95rfhxzxlq3zrrj2z2kqylx2jp8g68lqu6alczdxd59lzp4hlfuj3jp54fp06xsaaay0uyass992g507tdd7psua5w6q76dyq3");

    let (_, address) = z_spending_key.default_address().unwrap();
    let encoded_addr = encode_payment_address(z_mainnet_constants::HRP_SAPLING_PAYMENT_ADDRESS, &address);
    assert_eq!(
        encoded_addr,
        "zs182ht30wnnnr8jjhj2j9v5dkx3qsknnr5r00jfwk2nczdtqy7w0v836kyy840kv2r8xle5gcl549"
    );
}
