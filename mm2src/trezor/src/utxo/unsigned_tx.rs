use crate::constants::TrezorCoin;
use crate::proto::messages_bitcoin as proto_bitcoin;
use crate::utxo::prev_tx::PrevTx;
use crate::{serialize_derivation_path, TrezorError, TrezorResult};
use common::mm_error::prelude::*;
use hw_common::primitives::DerivationPath;

/// https://github.com/trezor/trezor-common/blob/master/protob/messages-bitcoin.proto#L16
#[derive(Clone, Copy)]
pub enum TrezorInputScriptType {
    /// Standard P2PKH address.
    SpendAddress,
    /// P2SH multisig address.
    SpendMultiSig,
    /// Reserved for external inputs (coinjoin).
    External,
    /// Native SegWit.
    SpendWitness,
    /// SegWit over P2SH (backward compatible).
    SpendP2SHWitness,
}

impl From<TrezorInputScriptType> for proto_bitcoin::InputScriptType {
    fn from(script: TrezorInputScriptType) -> Self {
        match script {
            TrezorInputScriptType::SpendAddress => proto_bitcoin::InputScriptType::SPENDADDRESS,
            TrezorInputScriptType::SpendMultiSig => proto_bitcoin::InputScriptType::SPENDMULTISIG,
            TrezorInputScriptType::External => proto_bitcoin::InputScriptType::EXTERNAL,
            TrezorInputScriptType::SpendWitness => proto_bitcoin::InputScriptType::SPENDWITNESS,
            TrezorInputScriptType::SpendP2SHWitness => proto_bitcoin::InputScriptType::SPENDP2SHWITNESS,
        }
    }
}

#[derive(Clone, Copy)]
pub enum TrezorOutputScriptType {
    /// Used for all addresses (bitcoin, p2sh, witness).
    PayToAddress,
    /// OP_RETURN.
    PayToOpReturn,
}

impl From<TrezorOutputScriptType> for proto_bitcoin::OutputScriptType {
    fn from(script: TrezorOutputScriptType) -> Self {
        match script {
            TrezorOutputScriptType::PayToAddress => proto_bitcoin::OutputScriptType::PAYTOADDRESS,
            TrezorOutputScriptType::PayToOpReturn => proto_bitcoin::OutputScriptType::PAYTOOPRETURN,
        }
    }
}

/// Missing fields:
/// * script_sig - https://docs.trezor.io/trezor-firmware/common/communication/bitcoin-signing.html#external-inputs
/// * multisig - filled if input is going to spend multisig tx
/// * decred_tree - only for Decred, 0 is a normal transaction while 1 is a stake transaction
/// * witness - witness data, only set for EXTERNAL inputs
/// * ownership_proof - SLIP-0019 proof of ownership, only set for EXTERNAL inputs
/// * commitment_data - optional commitment data for the SLIP-0019 proof of ownership
/// * orig_hash - tx_hash of the original transaction where this input was spent (used when creating a replacement transaction)
/// * orig_index - index of the input in the original transaction (used when creating a replacement transaction)
/// * decred_staking_spend - if not None this holds the type of stake spend: revocation or stake generation
pub struct UnsignedTxInput {
    /// BIP-32 path to derive the key from master node.
    /// TODO I guess this field shouldn't be set if the input script type is Multisig, for example.
    pub address_derivation_path: Option<DerivationPath>,
    /// Info of previous transaction.
    pub prev_tx: PrevTx,
    /// Hash of previous transaction output to spend by this input.
    pub prev_hash: Vec<u8>,
    /// Index of previous output to spend.
    pub prev_index: u32,
    /// Sequence.
    pub sequence: u32,
    /// Defines template of input script.
    pub input_script_type: TrezorInputScriptType,
    /// Amount of previous transaction output.
    pub amount: u64,
}

impl UnsignedTxInput {
    fn to_proto(&self) -> proto_bitcoin::TxAckInput {
        let mut input = proto_bitcoin::TxInput::default();
        if let Some(ref address_derivation_path) = self.address_derivation_path {
            input.set_address_n(serialize_derivation_path(address_derivation_path));
        }
        input.set_prev_hash(self.prev_hash.clone());
        input.set_prev_index(self.prev_index);
        input.set_sequence(self.sequence);
        input.set_script_type(self.input_script_type.into());
        input.set_amount(self.amount);

        let mut input_ack_wrapper = proto_bitcoin::TxAckInput_TxAckInputWrapper::default();
        input_ack_wrapper.set_input(input);

        let mut input_ack = proto_bitcoin::TxAckInput::default();
        input_ack.set_tx(input_ack_wrapper);
        input_ack
    }
}

/// Missing fields:
/// * address_n - BIP-32 path to derive the key from master node | TODO consider adding the field
/// * multisig - defines multisig address; script_type must be PAYTOMULTISIG
/// * op_return_data - defines op_return data; script_type must be PAYTOOPRETURN, amount must be 0
/// * orig_hash - tx_hash of the original transaction where this output was present (used when creating a replacement transaction)
/// * orig_index - index of the output in the original transaction (used when creating a replacement transaction)
pub struct TxOutput {
    /// Destination address in Base58 encoding; script_type must be PAYTOADDRESS.
    pub address: String,
    /// Amount to spend in satoshis.
    pub amount: u64,
    /// Output script type.
    pub script_type: TrezorOutputScriptType,
}

impl TxOutput {
    fn to_proto(&self) -> proto_bitcoin::TxAckOutput {
        let mut output = proto_bitcoin::TxOutput::default();
        output.set_address(self.address.clone());
        output.set_amount(self.amount);
        output.set_script_type(proto_bitcoin::OutputScriptType::from(self.script_type));

        let mut ack_output_wrapper = proto_bitcoin::TxAckOutput_TxAckOutputWrapper::new();
        ack_output_wrapper.set_output(output);

        let mut ack_output = proto_bitcoin::TxAckOutput::new();
        ack_output.set_tx(ack_output_wrapper);
        ack_output
    }
}

/// Missing fields:
/// * expiry_height - only for Decred and Zcash
/// * overwintered - deprecated in 2.3.2, the field is not needed as it can be derived from `version`.
///                  The main reason why it's ignored is that this can be requested asa extra data:
///                  https://docs.trezor.io/trezor-firmware/common/communication/bitcoin-signing.html#extra-data
pub struct UnsignedUtxoTx {
    pub coin: TrezorCoin,
    /// Transaction inputs.
    pub inputs: Vec<UnsignedTxInput>,
    /// Transaction outputs.
    pub outputs: Vec<TxOutput>,
    /// Transaction version.
    pub version: u32,
    /// Transaction lock_time.
    pub lock_time: u32,
    /// only for Zcash, nVersionGroupId.
    pub version_group_id: Option<u32>,
    /// only for Zcash, BRANCH_ID.
    pub branch_id: Option<u32>,
}

impl UnsignedUtxoTx {
    pub(crate) fn sign_tx_message(&self) -> proto_bitcoin::SignTx {
        let mut input = proto_bitcoin::SignTx::default();
        input.set_coin_name(self.coin.to_string());
        input.set_inputs_count(self.inputs.len() as u32);
        input.set_outputs_count(self.outputs.len() as u32);
        input.set_version(self.version);
        input.set_lock_time(self.lock_time);
        if let Some(version_group_id) = self.version_group_id {
            input.set_version_group_id(version_group_id);
        }
        if let Some(branch_id) = self.branch_id {
            input.set_branch_id(branch_id);
        }
        input
    }

    pub(crate) fn prev_tx(&self, hash: &[u8]) -> TrezorResult<&PrevTx> {
        self.inputs
            .iter()
            .find(|input| input.prev_hash == hash)
            .map(|input| &input.prev_tx)
            .or_mm_err(|| {
                let error = format!("Previous tx not found by the hash '{:?}'", hash);
                TrezorError::ProtocolError(error)
            })
    }

    pub(crate) fn input_message(&self, input_index: usize) -> TrezorResult<proto_bitcoin::TxAckInput> {
        match self.inputs.get(input_index) {
            Some(prev_input) => Ok(prev_input.to_proto()),
            None => {
                let error = format!(
                    "Unexpected index '{}' of the tx input. Actual count of inputs: {}",
                    input_index,
                    self.inputs.len()
                );
                MmError::err(TrezorError::ProtocolError(error))
            },
        }
    }

    pub(crate) fn output_message(&self, output_index: usize) -> TrezorResult<proto_bitcoin::TxAckOutput> {
        match self.outputs.get(output_index) {
            Some(prev_output) => Ok(prev_output.to_proto()),
            None => {
                let error = format!(
                    "Unexpected index '{}' of the tx output. Actual count of outputs: {}",
                    output_index,
                    self.outputs.len()
                );
                MmError::err(TrezorError::ProtocolError(error))
            },
        }
    }
}
