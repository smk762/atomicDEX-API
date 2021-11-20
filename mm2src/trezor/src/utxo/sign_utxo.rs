use crate::proto::messages_bitcoin as proto_bitcoin;
use crate::utxo::unsigned_tx::UnsignedUtxoTx;
use crate::utxo::Signature;
use crate::{TrezorClient, TrezorError, TrezorResponse, TrezorResult};
use common::log::{debug, info};
use common::mm_error::prelude::*;

pub struct TxSignResult {
    pub signatures: Vec<Signature>,
    pub serialized_tx: Vec<u8>,
}

impl TxSignResult {
    fn new_with_inputs_count(inputs_count: usize) -> TxSignResult {
        TxSignResult {
            signatures: vec![Signature::new(); inputs_count],
            serialized_tx: Vec::new(),
        }
    }
}

impl TrezorClient {
    /// https://docs.trezor.io/trezor-firmware/common/communication/bitcoin-signing.html#pseudo-code
    /// TODO add a `timeout` param.
    ///
    /// # Fail
    ///
    /// Currently, this method fails if a device requests a PIN.
    pub async fn sign_utxo_tx(&self, unsigned: UnsignedUtxoTx) -> TrezorResult<TxSignResult> {
        use proto_bitcoin::TxRequest_RequestType as ProtoTxRequestType;

        let mut result = TxSignResult::new_with_inputs_count(unsigned.inputs.len());
        // Please note `tx_request` is changed within the following loop.
        let mut tx_request = self.sign_tx(unsigned.sign_tx_message()).await?.ack_all().await?;

        info!(
            "Start transaction signing: COIN={} INPUTS_COUNT={} OUTPUTS_COUNT={} OVERWINTERED={}",
            unsigned.coin,
            unsigned.inputs.len(),
            unsigned.outputs.len(),
            unsigned.version_group_id.is_some() || unsigned.branch_id.is_some()
        );

        loop {
            extract_serialized_data(&tx_request, &mut result)?;

            let request_type = tx_request.get_request_type();
            if request_type == ProtoTxRequestType::TXFINISHED {
                return Ok(result);
            }

            let tx_request_details = tx_request.get_details();
            let is_prev = tx_request_details.has_tx_hash();

            debug!("TxRequest: REQUEST_TYPE={:?} PREV={}", request_type, is_prev);

            tx_request = match request_type {
                ProtoTxRequestType::TXINPUT if is_prev => self.send_prev_input(&unsigned, tx_request_details).await?,
                ProtoTxRequestType::TXINPUT => self.send_input(&unsigned, tx_request_details).await?,
                ProtoTxRequestType::TXOUTPUT if is_prev => self.send_prev_output(&unsigned, tx_request_details).await?,
                ProtoTxRequestType::TXOUTPUT => self.send_output(&unsigned, tx_request_details).await?,
                ProtoTxRequestType::TXMETA if is_prev => self.send_prev_tx_meta(&unsigned, tx_request_details).await?,
                ProtoTxRequestType::TXEXTRADATA if is_prev => {
                    self.send_extra_data(&unsigned, tx_request_details).await?
                },
                _ => {
                    let error = format!("Unexpected tx request: {:?}, is_prev: {}", request_type, is_prev);
                    return MmError::err(TrezorError::ProtocolError(error));
                },
            };
        }
    }

    async fn send_prev_tx_meta(
        &self,
        unsigned: &UnsignedUtxoTx,
        request_details: &proto_bitcoin::TxRequest_TxRequestDetailsType,
    ) -> TrezorResult<proto_bitcoin::TxRequest> {
        let prev_tx_hash = request_details.get_tx_hash();
        let prev_tx = unsigned.prev_tx(prev_tx_hash)?;
        let req = prev_tx.meta_message();

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ack_all().await
    }

    async fn send_prev_input(
        &self,
        unsigned: &UnsignedUtxoTx,
        request_details: &proto_bitcoin::TxRequest_TxRequestDetailsType,
    ) -> TrezorResult<proto_bitcoin::TxRequest> {
        let prev_tx_hash = request_details.get_tx_hash();
        let prev_input_index = request_details.get_request_index() as usize;

        let prev_tx = unsigned.prev_tx(prev_tx_hash)?;
        let req = prev_tx.input_message(prev_input_index)?;

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ack_all().await
    }

    async fn send_prev_output(
        &self,
        unsigned: &UnsignedUtxoTx,
        request_details: &proto_bitcoin::TxRequest_TxRequestDetailsType,
    ) -> TrezorResult<proto_bitcoin::TxRequest> {
        let prev_tx_hash = request_details.get_tx_hash();
        let prev_output_index = request_details.get_request_index() as usize;

        let prev_tx = unsigned.prev_tx(prev_tx_hash)?;
        let req = prev_tx.output_message(prev_output_index)?;

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ack_all().await
    }

    async fn send_input(
        &self,
        unsigned: &UnsignedUtxoTx,
        request_details: &proto_bitcoin::TxRequest_TxRequestDetailsType,
    ) -> TrezorResult<proto_bitcoin::TxRequest> {
        let input_index = request_details.get_request_index() as usize;
        let req = unsigned.input_message(input_index)?;

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ack_all().await
    }

    async fn send_output(
        &self,
        unsigned: &UnsignedUtxoTx,
        request_details: &proto_bitcoin::TxRequest_TxRequestDetailsType,
    ) -> TrezorResult<proto_bitcoin::TxRequest> {
        let output_index = request_details.get_request_index() as usize;
        let req = unsigned.output_message(output_index)?;

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ack_all().await
    }

    async fn send_extra_data(
        &self,
        unsigned: &UnsignedUtxoTx,
        request_details: &proto_bitcoin::TxRequest_TxRequestDetailsType,
    ) -> TrezorResult<proto_bitcoin::TxRequest> {
        let offset = request_details.get_extra_data_offset() as usize;
        let len = request_details.get_extra_data_len() as usize;
        let prev_tx_hash = request_details.get_tx_hash();

        let prev_tx = unsigned.prev_tx(prev_tx_hash)?;
        let req = prev_tx.extra_data_message(offset, len)?;

        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await?.ack_all().await
    }

    async fn sign_tx(&self, req: proto_bitcoin::SignTx) -> TrezorResult<TrezorResponse<proto_bitcoin::TxRequest>> {
        let result_handler = Box::new(Ok);
        self.call(req, result_handler).await
    }
}

fn extract_serialized_data(tx_request: &proto_bitcoin::TxRequest, result: &mut TxSignResult) -> TrezorResult<()> {
    if !tx_request.has_serialized() {
        return Ok(());
    }
    let serialized = tx_request.get_serialized();

    if serialized.has_signature() && serialized.has_signature_index() {
        let input_index = serialized.get_signature_index() as usize;
        if input_index >= result.signatures.len() {
            let error = format!(
                "Received a signature of unknown Transaction Input: {}. Number of inputs: {}",
                input_index,
                result.signatures.len()
            );
            return MmError::err(TrezorError::ProtocolError(error));
        }

        result.signatures[input_index] = serialized.get_signature().to_vec();
    }

    if serialized.has_serialized_tx() {
        result.serialized_tx.extend_from_slice(serialized.get_serialized_tx());
    }

    Ok(())
}
