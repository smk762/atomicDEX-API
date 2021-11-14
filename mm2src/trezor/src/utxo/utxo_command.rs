use crate::client::TrezorClient;
use crate::constants::TrezorCoin;
use crate::proto::messages_bitcoin as proto_bitcoin;
use crate::response_channel::{response_loop, trezor_response_channel, TrezorResponseReceiver};
use crate::{ecdsa_curve_to_string, serialize_derivation_path, TrezorResult};
use common::executor::spawn;
use futures::future::{select, FutureExt};
use hw_common::primitives::{DerivationPath, EcdsaCurve};

// Bitcoin(UTXO) operations.
impl TrezorClient {
    pub fn get_utxo_address(
        &self,
        path: DerivationPath,
        coin: TrezorCoin,
    ) -> TrezorResponseReceiver<TrezorResult<String>> {
        let trezor = self.clone();
        let (response_tx, response_rx, shutdown_rx) = trezor_response_channel();
        let fut = async move {
            let mut req = proto_bitcoin::GetAddress::default();
            req.set_address_n(serialize_derivation_path(&path));
            req.set_coin_name(coin.to_string());

            let result_handler = Box::new(|m: proto_bitcoin::Address| Ok(m.get_address().to_string()));
            let result = trezor.call(req, result_handler).await;
            response_loop(response_tx, result).await;
        }
        .boxed();
        let fut_with_shutdown = select(fut, shutdown_rx).map(|_| ());
        spawn(fut_with_shutdown);

        response_rx
    }

    pub fn get_public_key(
        &self,
        path: DerivationPath,
        coin: TrezorCoin,
        ecdsa_curve: EcdsaCurve,
    ) -> TrezorResponseReceiver<TrezorResult<String>> {
        let trezor = self.clone();
        let (response_tx, response_rx, shutdown_rx) = trezor_response_channel();
        let fut = async move {
            let mut req = proto_bitcoin::GetPublicKey::default();
            req.set_address_n(serialize_derivation_path(&path));
            req.set_coin_name(coin.to_string());
            req.set_ecdsa_curve_name(ecdsa_curve_to_string(ecdsa_curve));

            let result_handler = Box::new(|m: proto_bitcoin::PublicKey| Ok(m.get_xpub().to_string()));
            let result = trezor.call(req, result_handler).await;
            response_loop(response_tx, result).await;
        }
        .boxed();
        let fut_with_shutdown = select(fut, shutdown_rx).map(|_| ());
        spawn(fut_with_shutdown);

        response_rx
    }
}
