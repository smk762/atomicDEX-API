use crate::proto::messages_bitcoin as proto_bitcoin;
use crate::utxo::{ScriptPubkey, Signature};
use crate::{TrezorError, TrezorResult};
use common::mm_error::prelude::*;

/// Missing fields:
/// * decred_tree - only for Decred
pub struct PrevTxInput {
    /// Hash of previous transaction output to spend by this input.
    pub prev_hash: Vec<u8>,
    /// Index of previous output to spend.
    pub prev_index: u32,
    /// Script signature.
    pub script_sig: Signature,
    /// Sequence.
    pub sequence: u32,
}

impl PrevTxInput {
    fn to_proto(&self) -> proto_bitcoin::TxAckPrevInput {
        let mut prev_input = proto_bitcoin::PrevInput::default();
        prev_input.set_prev_hash(self.prev_hash.clone());
        prev_input.set_prev_index(self.prev_index);
        prev_input.set_script_sig(self.script_sig.clone());
        prev_input.set_sequence(self.sequence);

        let mut ack_prev_input_wrapper = proto_bitcoin::TxAckPrevInput_TxAckPrevInputWrapper::default();
        ack_prev_input_wrapper.set_input(prev_input);

        let mut ack_prev_input = proto_bitcoin::TxAckPrevInput::default();
        ack_prev_input.set_tx(ack_prev_input_wrapper);
        ack_prev_input
    }
}

/// Missing fields:
/// * decred_script_version - only for Decred
pub struct PrevTxOutput {
    /// Amount sent to this output.
    pub amount: u64,
    /// Script Pubkey of this output.
    pub script_pubkey: ScriptPubkey,
}

impl PrevTxOutput {
    fn to_proto(&self) -> proto_bitcoin::TxAckPrevOutput {
        let mut prev_output = proto_bitcoin::PrevOutput::default();
        prev_output.set_amount(self.amount);
        prev_output.set_script_pubkey(self.script_pubkey.clone());

        let mut ack_prev_output_wrapper = proto_bitcoin::TxAckPrevOutput_TxAckPrevOutputWrapper::default();
        ack_prev_output_wrapper.set_output(prev_output);

        let mut ack_prev_output = proto_bitcoin::TxAckPrevOutput::default();
        ack_prev_output.set_tx(ack_prev_output_wrapper);
        ack_prev_output
    }
}

/// Missing fields:
/// * extra_data_len - only for Dash, Zcash
/// * expiry - only for Decred and Zcash
/// * optional uint32 version_group_id = 12;  // only for Zcash, nVersionGroupId
/// * timestamp - only for Peercoin
/// * branch_id - only for Zcash, BRANCH_ID
pub struct PrevTx {
    /// Transaction inputs.
    pub inputs: Vec<PrevTxInput>,
    /// Transaction outputs.
    pub outputs: Vec<PrevTxOutput>,
    /// Transaction version.
    pub version: u32,
    /// Transaction lock_time.
    pub lock_time: u32,
}

impl PrevTx {
    pub(crate) fn meta_message(&self) -> proto_bitcoin::TxAckPrevMeta {
        let mut prev = proto_bitcoin::PrevTx::default();
        prev.set_version(self.version);
        prev.set_lock_time(self.lock_time);
        prev.set_inputs_count(self.inputs.len() as u32);
        prev.set_outputs_count(self.outputs.len() as u32);

        let mut ack_prev_meta = proto_bitcoin::TxAckPrevMeta::default();
        ack_prev_meta.set_tx(prev);
        ack_prev_meta
    }

    pub(crate) fn input_message(&self, input_index: usize) -> TrezorResult<proto_bitcoin::TxAckPrevInput> {
        match self.inputs.get(input_index) {
            Some(prev_input) => Ok(prev_input.to_proto()),
            None => {
                let error = format!(
                    "Unexpected index '{}' of the prev-tx input. Actual count of inputs: {}",
                    input_index,
                    self.inputs.len()
                );
                MmError::err(TrezorError::ProtocolError(error))
            },
        }
    }

    pub(crate) fn output_message(&self, output_index: usize) -> TrezorResult<proto_bitcoin::TxAckPrevOutput> {
        match self.outputs.get(output_index) {
            Some(prev_output) => Ok(prev_output.to_proto()),
            None => {
                let error = format!(
                    "Unexpected index '{}' of the prev-tx output. Actual count of outputs: {}",
                    output_index,
                    self.outputs.len()
                );
                MmError::err(TrezorError::ProtocolError(error))
            },
        }
    }
}
