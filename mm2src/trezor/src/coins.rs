use derive_more::Display;

#[derive(Debug, Display)]
pub enum TrezorCoin {
    Bitcoin,
    Komodo,
}
