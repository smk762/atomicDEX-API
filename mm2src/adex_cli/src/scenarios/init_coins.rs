use common::log::{error, info};
use derive_more::Display;
use hyper::{body::Bytes, client::Client, Uri};
use hyper_tls::HttpsConnector;

use super::helpers::rewrite_data_file;

const FULL_COIN_SET_ADDRESS: &str = "https://raw.githubusercontent.com/KomodoPlatform/coins/master/coins";
const EMPTY_COIN_SET_DATA: &str = r"[]\n";

#[derive(Clone, Copy, Debug, Display)]
pub enum CoinSet {
    Empty,
    Full,
}

#[tokio::main(flavor = "current_thread")]
pub async fn init_coins(coins_file: &str) -> Result<(), ()> {
    let coin_set = inquire_coin_set(coins_file)?;
    info!("Start getting mm2 coins");

    let bytes_got;
    let coins_data = match coin_set {
        CoinSet::Empty => EMPTY_COIN_SET_DATA.as_bytes(),
        CoinSet::Full => {
            info!("Getting coin set from: {FULL_COIN_SET_ADDRESS}");
            bytes_got = get_coins_from_remote(FULL_COIN_SET_ADDRESS).await?;
            bytes_got.as_ref()
        },
    };

    rewrite_data_file(coins_data, coins_file)?;
    info!("Got coins data, written into: {coins_file}");
    Ok(())
}

fn inquire_coin_set(coins_file: &str) -> Result<CoinSet, ()> {
    inquire::Select::new(
        format!("Select one of predefined coin sets to save into: {coins_file}").as_str(),
        vec![CoinSet::Empty, CoinSet::Full],
    )
    .with_help_message("Information about the currencies: their ticker symbols, names, ports, addresses, etc.")
    .prompt()
    .map_err(|error| {
        error!("Failed to select coin_set: {error}");
    })
}

async fn get_coins_from_remote(address: &'static str) -> Result<Bytes, ()> {
    let connector = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(connector);
    let coins_data = client.get(Uri::from_static(address)).await.map_err(|error| {
        error!("Failed to get coins from {address}: {error}");
    })?;

    hyper::body::to_bytes(coins_data).await.map_err(|error| {
        error!("Failed to get bytes from response: {error}");
    })
}
